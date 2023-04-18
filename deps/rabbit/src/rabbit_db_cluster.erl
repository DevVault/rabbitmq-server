%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2023 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(rabbit_db_cluster).

-include_lib("kernel/include/logger.hrl").

-include_lib("rabbit_common/include/logging.hrl").

-export([join/2,
         forget_member/2]).
-export([change_node_type/1]).
-export([is_clustered/0,
         members/0,
         disc_members/0,
         node_type/0,
         check_consistency/0,
         cli_cluster_status/0]).

%% These two functions are not supported by Khepri and probably
%% shouldn't be part of this API in the future, but currently
%% they're needed here so they can fail when invoked using Khepri.
-export([rename/2,
         update_cluster_nodes/1]).

-type node_type() :: disc_node_type() | ram_node_type().
-type disc_node_type() :: disc.
-type ram_node_type() :: ram.

-export_type([node_type/0, disc_node_type/0, ram_node_type/0]).

-define(
   IS_NODE_TYPE(NodeType),
   ((NodeType) =:= disc orelse (NodeType) =:= ram)).

%% -------------------------------------------------------------------
%% Cluster formation.
%% -------------------------------------------------------------------

-spec join(RemoteNode, NodeType) -> Ret when
      RemoteNode :: node(),
      NodeType :: rabbit_db_cluster:node_type(),
      Ret :: Ok | Error,
      Ok :: ok | {ok, already_member},
      Error :: {error, {inconsistent_cluster, string()}}.
%% @doc Adds this node to a cluster using `RemoteNode' to reach it.

join(RemoteNode, NodeType)
  when is_atom(RemoteNode) andalso ?IS_NODE_TYPE(NodeType) ->
    ?LOG_DEBUG(
      "DB: joining cluster using remote node `~ts`", [RemoteNode],
       #{domain => ?RMQLOG_DOMAIN_DB}),
    case rabbit_db:run(
           #{mnesia => fun() -> join_using_mnesia(RemoteNode, NodeType) end,
             khepri => fun() -> join_using_khepri(RemoteNode, NodeType) end
            }) of
        ok ->
            rabbit_node_monitor:notify_joined_cluster(),
            ok;
        Other ->
            Other
    end.

join_using_mnesia(RemoteNode, NodeType) ->
    rabbit_mnesia:join_cluster(RemoteNode, NodeType).

join_using_khepri(_RemoteNode, ram) ->
    rabbit_log:warning("Join node with --ram flag is not supported by Khepri. Skipping..."),
    {error, not_supported};
join_using_khepri(RemoteNode, NodeType) ->
    case rabbit_khepri:check_join_cluster(RemoteNode) of
        ok ->
            case join_using_mnesia(RemoteNode, NodeType) of
                ok ->
                    rabbit_khepri:init_cluster();
                {ok, already_member} ->
                    rabbit_khepri:init_cluster();
                Error ->
                    Error
            end;
        {ok, already_member} ->
            join_using_mnesia(RemoteNode, NodeType);
        Error ->
            Error
    end.

-spec forget_member(Node, RemoveWhenOffline) -> ok when
      Node :: node(),
      RemoveWhenOffline :: boolean().
%% @doc Removes `Node' from the cluster.

forget_member(Node, RemoveWhenOffline) ->
    rabbit_db:run(
      #{mnesia => fun() -> forget_member_using_mnesia(Node, RemoveWhenOffline) end,
        khepri => fun() ->
                          case forget_member_using_khepri(Node, RemoveWhenOffline) of
                              ok ->
                                  forget_member_using_mnesia(Node, RemoveWhenOffline);
                              Error ->
                                  Error
                          end
                  end
       }).

forget_member_using_mnesia(Node, RemoveWhenOffline) ->
    rabbit_mnesia:forget_cluster_node(Node, RemoveWhenOffline).

forget_member_using_khepri(_Node, true) ->
    rabbit_log:warning("Remove node with --offline flag is not supported by Khepri. Skipping..."),
    {error, not_supported};
forget_member_using_khepri(Node, false = _RemoveWhenOffline) ->
    rabbit_khepri:leave_cluster(Node).

%% -------------------------------------------------------------------
%% Cluster update.
%% -------------------------------------------------------------------

-spec change_node_type(NodeType) -> ok when
      NodeType :: rabbit_db_cluster:node_type().
%% @doc Changes the node type to `NodeType'.
%%
%% Node types may not all be valid with all databases.

change_node_type(NodeType) ->
    rabbit_db:run(
      #{mnesia => fun() -> change_node_type_using_mnesia(NodeType) end,
        khepri => fun() -> change_node_type_using_khepri(NodeType) end
       }).

change_node_type_using_mnesia(NodeType) ->
    rabbit_mnesia:change_cluster_node_type(NodeType).

change_node_type_using_khepri(_NodeType) ->
    rabbit_log:warning("Change cluster node type is not supported by Khepri. Only disc nodes are allowed. Skipping..."),
    {error, not_supported}.

%% -------------------------------------------------------------------
%% Cluster status.
%% -------------------------------------------------------------------

-spec is_clustered() -> IsClustered when
      IsClustered :: boolean().
%% @doc Indicates if this node is clustered with other nodes or not.

is_clustered() ->
    rabbit_db:run(
      #{mnesia => fun() -> is_clustered_using_mnesia() end,
        khepri => fun() -> is_clustered_using_khepri() end
       }).

is_clustered_using_mnesia() ->
    rabbit_mnesia:is_clustered().

is_clustered_using_khepri() ->
    rabbit_khepri:is_clustered().

-spec members() -> Members when
      Members :: [node()].
%% @doc Returns the list of cluster members.

members() ->
    rabbit_db:run(
      #{mnesia => fun() -> members_using_mnesia() end,
        khepri => fun() -> members_using_khepri() end
       }).

members_using_mnesia() ->
    case rabbit_mnesia:is_running() andalso rabbit_table:is_present() of
        true ->
            %% If Mnesia is running locally and some tables exist, we can know
            %% the database was initialized and we can query the list of
            %% members.
            mnesia:system_info(db_nodes);
        false ->
            try
                %% When Mnesia is not running, we fall back to reading the
                %% cluster status files stored on disk, if they exist.
                {Members, _, _} = rabbit_node_monitor:read_cluster_status(),
                Members
            catch
                throw:{error, _Reason}:_Stacktrace ->
                    %% If we couldn't read those files, we consider that only
                    %% this node is part of the "cluster".
                    [node()]
            end
    end.

members_using_khepri() ->
    rabbit_khepri:nodes().

-spec disc_members() -> Members when
      Members :: [node()].
%% @private

disc_members() ->
    rabbit_db:run(
      #{mnesia => fun() -> disc_members_using_mnesia() end,
        khepri => fun() -> members_using_khepri() end
       }).

disc_members_using_mnesia() ->
    rabbit_mnesia:cluster_nodes(disc).

-spec node_type() -> NodeType when
      NodeType :: rabbit_db_cluster:node_type().
%% @doc Returns the type of this node, `disc' or `ram'.
%%
%% Node types may not all be relevant with all databases.

node_type() ->
    rabbit_db:run(
      #{mnesia => fun() -> node_type_using_mnesia() end,
        khepri => fun() -> node_type_using_khepri() end
       }).

node_type_using_mnesia() ->
    rabbit_mnesia:node_type().

node_type_using_khepri() ->
    disc.

-spec check_consistency() -> ok.
%% @doc Ensures the cluster is consistent.

check_consistency() ->
    rabbit_db:run(
      #{mnesia => fun() -> check_consistency_using_mnesia() end,
        khepri => fun() -> case check_consistency_using_khepri() of
                               ok -> check_consistency_using_mnesia();
                               Error -> Error
                           end
                  end
       }).

check_consistency_using_mnesia() ->
    rabbit_mnesia:check_cluster_consistency().

check_consistency_using_khepri() ->
    rabbit_khepri:check_cluster_consistency().

-spec cli_cluster_status() -> ClusterStatus when
      ClusterStatus :: [{nodes, [{rabbit_db_cluster:node_type(), [node()]}]} |
                        {running_nodes, [node()]} |
                        {partitions, [{node(), [node()]}]}].
%% @doc Returns information from the cluster for the `cluster_status' CLI
%% command.

cli_cluster_status() ->
    rabbit_db:run(
      #{mnesia => fun() -> cli_cluster_status_using_mnesia() end,
        khepri => fun() -> cli_cluster_status_using_khepri() end
       }).

cli_cluster_status_using_mnesia() ->
    rabbit_mnesia:status().

cli_cluster_status_using_khepri() ->
    rabbit_khepri:cli_cluster_status().

rename(Node, NodeMapList) ->
    rabbit_db:run(
      #{mnesia => fun() -> rabbit_mnesia_rename:rename(Node, NodeMapList) end,
        khepri => fun() -> {error, not_supported} end
       }).

update_cluster_nodes(DiscoveryNode) ->
    rabbit_db:run(
      #{mnesia => fun() -> rabbit_mnesia:update_cluster_nodes(DiscoveryNode) end,
        khepri => fun() -> {error, not_supported} end
       }).
