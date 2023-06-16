%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2023 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(rabbit_oauth2_config).

-compile(export_all).

-define(APP, rabbitmq_auth_backend_oauth2).
-define(DEFAULT_PREFERRED_USERNAME_CLAIMS, [<<"sub">>, <<"client_id">>]).

-define(TOP_RESOURCE_SERVER_ID, application:get_env(?APP, resource_server_id)).

-spec get_default_preferred_username_claims() -> list().
get_default_preferred_username_claims() ->
  ?DEFAULT_PREFERRED_USERNAME_CLAIMS.

-spec get_preferred_username_claims() -> list().
get_preferred_username_claims() ->
  case application:get_env(?APP, preferred_username_claims) of
    {ok, Value} ->  append_or_return_default(Value, ?DEFAULT_PREFERRED_USERNAME_CLAIMS);
    _ -> ?DEFAULT_PREFERRED_USERNAME_CLAIMS
  end.

-spec add_signing_key(binary(), binary()) -> {ok, map()} | {error, term()}.
add_signing_key(KeyId, Key) ->
  LockId = rabbit_oauth2_config:lock(),
  try do_add_signing_key(KeyId, Key) of
    V -> V
  after
    rabbit_oauth2_config:unlock(LockId)
  end.

-spec add_signing_key(binary(), binary(), binary()) -> {ok, map()} | {error, term()}.
add_signing_key(ResourceServerId, KeyId, Key) ->
  LockId = rabbit_oauth2_config:lock(),
  try do_add_signing_key(ResourceServerId, KeyId, Key) of
    V -> V
  after
    rabbit_oauth2_config:unlock(LockId)
  end.

do_add_signing_key(KeyId, Key) ->
  do_replace_signing_keys(maps:put(KeyId, Key, get_signing_keys())).

do_add_signing_key(ResourceServerId, KeyId, Key) ->
  do_replace_signing_keys(ResourceServerId, maps:put(KeyId, Key, get_signing_keys(ResourceServerId))).

remove_signing_key(KeyId) ->
  LockId = rabbit_oauth2_config:lock(),
  try do_remove_signing_key(KeyId) of
    _ -> ok
  after
    rabbit_oauth2_config:unlock(LockId)
  end.

do_remove_signing_key(KeyId) ->
  do_replace_signing_keys(maps:remove(KeyId, get_signing_keys())).

do_remove_signing_key(ResourceServerId, KeyId) ->
  do_replace_signing_keys(maps:remove(KeyId, get_signing_keys(ResourceServerId))).


replace_signing_keys(SigningKeys) ->
  LockId = rabbit_oauth2_config:lock(),
  try do_replace_signing_keys(SigningKeys) of
    V -> V
  after
    rabbit_oauth2_config:unlock(LockId)
  end.

replace_signing_keys(ResourceServerId, SigningKeys) ->
  LockId = rabbit_oauth2_config:lock(),
  try do_replace_signing_keys(ResourceServerId, SigningKeys) of
    V -> V
  after
    rabbit_oauth2_config:unlock(LockId)
  end.

do_replace_signing_keys(SigningKeys) ->
  KeyConfig = application:get_env(?APP, key_config, []),
  KeyConfig1 = proplists:delete(signing_keys, KeyConfig),
  KeyConfig2 = [{signing_keys, SigningKeys} | KeyConfig1],
  application:set_env(?APP, key_config, KeyConfig2),
  SigningKeys.

do_replace_signing_keys(ResourceServerId, SigningKeys) ->
  do_replace_signing_keys(get_root_resource_server_id(), ResourceServerId, SigningKeys).

do_replace_signing_keys(TopResourceServerId, ResourceServerId, SigningKeys) when ResourceServerId =:= TopResourceServerId ->
  do_replace_signing_keys(SigningKeys);

do_replace_signing_keys(TopResourceServerId, ResourceServerId, SigningKeys) when ResourceServerId =/= TopResourceServerId ->
  ResourceServers = application:get_env(?APP, resource_servers, #{}),

  ResourceServer = maps:get(ResourceServerId, ResourceServers, []),
  KeyConfig0 = proplists:get_value(key_config, ResourceServer, []),
  KeyConfig1 = proplists:delete(signing_keys, KeyConfig0),
  KeyConfig2 = [{signing_keys, SigningKeys} | KeyConfig1],

  KeyConfig1 = proplists:delete(signing_keys, KeyConfig0),

  ResourceServer1 = proplists:delete(key_config, ResourceServer),
  ResourceServer2 = [{key_config, KeyConfig2} | ResourceServer1],

  application:set_env(?APP, resource_servers, maps:put(ResourceServerId, ResourceServer2, ResourceServers)),
  SigningKeys.

-spec get_signing_keys() -> map().
get_signing_keys() -> proplists:get_value(signing_keys, get_key_config(), #{}).

-spec get_signing_keys(binary()) -> map().
get_signing_keys(ResourceServerId) -> get_signing_keys(get_root_resource_server_id(), ResourceServerId).

get_signing_keys(TopResourceServerId, ResourceServerId) when ResourceServerId =:= TopResourceServerId ->
  get_signing_keys();
get_signing_keys(TopResourceServerId, ResourceServerId) when ResourceServerId =/= TopResourceServerId ->
  proplists:get_value(signing_keys, get_key_config(ResourceServerId), #{}).

-spec get_key_config() -> list().
get_key_config() -> application:get_env(?APP, key_config, []).

-spec get_key_config(binary()) -> list().
get_key_config(ResourceServerId) -> get_key_config(get_root_resource_server_id(), ResourceServerId).
get_key_config(TopResourceServerId, ResourceServerId) when ResourceServerId =:= TopResourceServerId ->
  get_key_config();
get_key_config(TopResourceServerId, ResourceServerId) when ResourceServerId =/= TopResourceServerId ->
  ResourceServers = application:get_env(?APP, resource_servers, #{}),
  ResourceServer = maps:get(ResourceServerId, ResourceServers, []),
  proplists:get_value(key_config, ResourceServer, get_key_config()).

get_signing_key(KeyId, ResourceServerId) -> get_signing_key(get_root_resource_server_id(), KeyId, ResourceServerId).

get_signing_key(TopResourceServerId, KeyId, ResourceServerId) when ResourceServerId =:= TopResourceServerId ->
  maps:get(KeyId, get_signing_keys(), undefined);
get_signing_key(TopResourceServerId, KeyId, ResourceServerId) when ResourceServerId =/= TopResourceServerId ->
  maps:get(KeyId, get_signing_keys(ResourceServerId), undefined).


get_jwks_url(ResourceServerId) ->
  proplists:get_value(jwks_url, get_key_config(ResourceServerId)).

append_or_return_default(ListOrBinary, Default) ->
  case ListOrBinary of
    VarList when is_list(VarList) -> VarList ++ Default;
    VarBinary when is_binary(VarBinary) -> [VarBinary] ++ Default;
    _ -> Default
  end.

-spec get_root_resource_server_id() -> binary() | {error, term()}.
get_root_resource_server_id() ->
  case ?TOP_RESOURCE_SERVER_ID of
    undefined -> {error, missing_token_audience_and_or_config_resource_server_id };
    {ok, ResourceServerId} -> ResourceServerId
  end.

-spec get_allowed_resource_server_ids() -> list().
get_allowed_resource_server_ids() ->
  ResourceServers = application:get_env(?APP, resource_servers, #{}),
  ResourceServerIds = maps:fold(fun(K, V, List) -> List ++ [proplists:get_value(id, V, K)] end, [], ResourceServers),
  ResourceServerIds ++ case get_root_resource_server_id() of
       {error, _} -> [];
       ResourceServerId -> [ ResourceServerId ]
  end.

-spec find_audience_in_resource_server_ids(binary() | list()) -> {ok, binary()} | {error, term()}.
find_audience_in_resource_server_ids(Audience) when is_binary(Audience) -> find_audience_in_resource_server_ids([Audience]);
find_audience_in_resource_server_ids(AudList) when is_list(AudList) ->
  AllowedAudList = get_allowed_resource_server_ids(),
  case intersection(AudList, AllowedAudList) of
   [One] -> {ok, One};
   [_One|_Tail] -> {error, only_one_resource_server_as_audience_found_many};
   [] -> {error, key_not_found}
  end.

-spec is_verify_aud() -> boolean().
is_verify_aud() ->
  application:get_env(?APP, verify_aud, true).

intersection(List1, List2) ->
    [I || I <- List1, lists:member(I, List2)].

lock() ->
    Nodes   = rabbit_nodes:list_running(),
    Retries = rabbit_nodes:lock_retries(),
    LockId = case global:set_lock({oauth2_config_lock, rabbitmq_auth_backend_oauth2}, Nodes, Retries) of
        true  -> rabbitmq_auth_backend_oauth2;
        false -> undefined
    end,
    LockId.

unlock(LockId) ->
    Nodes = rabbit_nodes:list_running(),
    case LockId of
        undefined -> ok;
        Value     ->
          global:del_lock({oauth2_config_lock, Value}, Nodes)
    end,
    ok.
