%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2023 VMware, Inc. or its affiliates.  All rights reserved.
%%

-module(rabbit_oauth2_config_SUITE).

-compile(export_all).

-include_lib("eunit/include/eunit.hrl").

-define(RABBITMQ,<<"rabbitmq">>).


all() ->
    [
        {group, other_group},
        {group, signing_key_group},
        {group, with_resource_server_id},
        {group, without_resource_server_id},
        {group, with_resource_servers},
        {group, with_resource_servers_and_resource_server_id},
        {group, inheritance_group}

    ].
groups() ->
    [
      {signing_key_group, [], [
          add_signing_keys_for_top_specific_resource_server,
          add_signing_keys_for_top_level_resource_server,

          replace_signing_keys_for_top_level_resource_server,
          replace_signing_keys_for_specific_resource_server
        ]
      },
      {other_group, [], [
          get_default_preferred_username_claims,
          get_preferred_username_claims
        ]
      },
      {with_resource_server_id, [], [
          get_root_resource_server_id,
          get_allowed_resource_server_ids_returns_resource_server_id,
          find_audience_in_resource_server_ids_found_resource_server_id,
          get_jwks_url_for_resource_server_id
        ]
      },
      {without_resource_server_id, [], [
          get_root_resource_server_id_returns_error,
          get_allowed_resource_server_ids_returns_empty_list
        ]
      },
      {with_resource_servers, [], [
          get_allowed_resource_server_ids_returns_resource_servers_ids,
          find_audience_in_resource_server_ids_found_one_resource_servers,
          get_jwks_url_for_resource_servers_id,
          index_resource_servers_by_id_else_by_key
        ]
      },
      {with_resource_servers_and_resource_server_id, [], [
          get_allowed_resource_server_ids_returns_all_resource_servers_ids,
          find_audience_in_resource_server_ids_found_resource_server_id,
          find_audience_in_resource_server_ids_found_one_resource_servers
        ]
      },
      {inheritance_group, [], [
          resolve_settings_via_inheritance,
          get_key_config
        ]
      }

    ].

init_per_suite(Config) ->
  rabbit_ct_helpers:log_environment(),
  rabbit_ct_helpers:run_setup_steps(Config).

end_per_suite(Config) ->
  rabbit_ct_helpers:run_teardown_steps(Config).

init_per_group(signing_key_group, Config) ->
  Config1 = rabbit_ct_helpers:set_config(Config, [
      {rmq_nodename_suffix, signing_key_group},
      {rmq_nodes_count, 1}
  ]),
  rabbit_ct_helpers:run_steps(Config1, rabbit_ct_broker_helpers:setup_steps());

init_per_group(with_resource_server_id, Config) ->
  application:set_env(rabbitmq_auth_backend_oauth2, resource_server_id, ?RABBITMQ),
  application:set_env(rabbitmq_auth_backend_oauth2, key_config, [{jwks_url,<<"https://oauth-for-rabbitmq">> }]),
  Config;

init_per_group(with_resource_servers_and_resource_server_id, Config) ->
  application:set_env(rabbitmq_auth_backend_oauth2, resource_server_id, ?RABBITMQ),
  application:set_env(rabbitmq_auth_backend_oauth2, key_config, [{jwks_url,<<"https://oauth-for-rabbitmq">> }]),
  application:set_env(rabbitmq_auth_backend_oauth2, resource_servers,
    #{<<"rabbitmq1">> =>  [ { key_config, [
                                            {jwks_url,<<"https://oauth-for-rabbitmq1">> }
                                          ]
                            }
                          ],
      <<"rabbitmq2">> =>  [ { key_config, [
                                            {jwks_url,<<"https://oauth-for-rabbitmq2">> }
                                          ]
                            }
                          ]
      }),
  Config;

init_per_group(with_resource_servers, Config) ->
  application:set_env(rabbitmq_auth_backend_oauth2, resource_servers,
    #{<<"rabbitmq1">> =>  [ { key_config, [
                                            {jwks_url,<<"https://oauth-for-rabbitmq1">> }
                                          ]
                            }
                          ],
      <<"rabbitmq2">> =>  [ { key_config, [
                                            {jwks_url,<<"https://oauth-for-rabbitmq2">> }
                                          ]
                            }
                          ],
      <<"0">> => [ {id, <<"rabbitmq-0">> } ],
      <<"1">> => [ {id, <<"rabbitmq-1">> } ]

      }),
  Config;

init_per_group(inheritance_group, Config) ->
  application:set_env(rabbitmq_auth_backend_oauth2, resource_server_id, ?RABBITMQ),
  application:set_env(rabbitmq_auth_backend_oauth2, scope_prefix, <<"some-prefix">>),
  application:set_env(rabbitmq_auth_backend_oauth2, additional_scopes_key, <<"roles">>),

  application:set_env(rabbitmq_auth_backend_oauth2, key_config, [ {jwks_url,<<"https://oauth-for-rabbitmq">> } ]
    ),

  application:set_env(rabbitmq_auth_backend_oauth2, resource_servers,
    #{<<"rabbitmq1">> =>  [ { key_config, [ {jwks_url,<<"https://oauth-for-rabbitmq1">> } ] } ],
      <<"rabbitmq2">> =>  [ {id, <<"rabbitmq-2">> } ]
      }
    ),
  Config;

init_per_group(_any, Config) ->
  Config.

end_per_group(signing_key_group, Config) ->
  rabbit_ct_helpers:run_steps(Config, rabbit_ct_broker_helpers:teardown_steps());

end_per_group(with_resource_server_id, Config) ->
  application:unset_env(rabbitmq_auth_backend_oauth2, resource_server_id),
  Config;

end_per_group(with_resource_servers_and_resource_server_id, Config) ->
  application:unset_env(rabbitmq_auth_backend_oauth2, resource_server_id),
  Config;

end_per_group(with_resource_servers, Config) ->
  application:unset_env(rabbitmq_auth_backend_oauth2, resource_servers),
  Config;


end_per_group(_any, Config) ->
  Config.

init_per_testcase(get_preferred_username_claims, Config) ->
  application:set_env(rabbitmq_auth_backend_oauth2, preferred_username_claims, [<<"username">>]),
  Config;

init_per_testcase(_TestCase, Config) ->
  Config.

end_per_testcase(get_preferred_username_claims, Config) ->
  application:unset_env(rabbitmq_auth_backend_oauth2, preferred_username_claims),
  Config;

end_per_testcase(_Testcase, Config) ->
  Config.

%% -----
get_default_preferred_username_claims(_Config) ->
  ?assertEqual(rabbit_oauth2_config:get_default_preferred_username_claims(),
    rabbit_oauth2_config:get_preferred_username_claims()).

get_preferred_username_claims(_Config) ->
  ?assertEqual([<<"username">>] ++ rabbit_oauth2_config:get_default_preferred_username_claims(),
    rabbit_oauth2_config:get_preferred_username_claims()).

call_add_signing_key(Config, Args) ->
  rabbit_ct_broker_helpers:rpc(Config, 0, rabbit_oauth2_config, add_signing_key, Args).

call_get_signing_keys(Config, Args) ->
  rabbit_ct_broker_helpers:rpc(Config, 0, rabbit_oauth2_config, get_signing_keys, Args).

call_add_signing_keys(Config, Args) ->
  rabbit_ct_broker_helpers:rpc(Config, 0, rabbit_oauth2_config, add_signing_keys, Args).

call_replace_signing_keys(Config, Args) ->
  rabbit_ct_broker_helpers:rpc(Config, 0, rabbit_oauth2_config, replace_signing_keys, Args).

add_signing_keys_for_top_level_resource_server(Config) ->
  #{<<"mykey-1">> := <<"some key 1">>} = call_add_signing_key(Config, [<<"mykey-1">>, <<"some key 1">>]),
  #{<<"mykey-1">> := <<"some key 1">>} = call_get_signing_keys(Config, []),

  #{<<"mykey-1">> := <<"some key 1">>, <<"mykey-2">> := <<"some key 2">>} = call_add_signing_key(Config, [<<"mykey-2">>, <<"some key 2">>]),
  #{<<"mykey-1">> := <<"some key 1">>, <<"mykey-2">> := <<"some key 2">>} = call_get_signing_keys(Config, []).

add_signing_keys_for_top_specific_resource_server(Config) ->
  #{<<"mykey-3-1">> := <<"some key 3-1">>} = call_add_signing_key(Config, [<<"my-resource-server-3">>, <<"mykey-3-1">>, <<"some key 3-1">>]),
  #{<<"mykey-4-1">> := <<"some key 4-1">>} = call_add_signing_key(Config, [<<"my-resource-server-4">>, <<"mykey-4-1">>, <<"some key 4-1">>]),
  #{<<"mykey-3-1">> := <<"some key 3-1">>} = call_get_signing_keys(Config, [<<"my-resource-server-3">>]),
  #{<<"mykey-4-1">> := <<"some key 4-1">>} = call_get_signing_keys(Config, [<<"my-resource-server-4">>]),

  #{<<"mykey-3-1">> := <<"some key 3-1">>, <<"mykey-3-2">> := <<"some key 3-2">>} = call_add_signing_key(Config, [<<"my-resource-server-3">>, <<"mykey-3-2">>, <<"some key 3-2">>]),

  #{<<"mykey-1">> := <<"some key 1">>} = call_add_signing_key(Config, [<<"mykey-1">>, <<"some key 1">>]),
  #{<<"mykey-1">> := <<"some key 1">>} = call_get_signing_keys(Config, []).

replace_signing_keys_for_top_level_resource_server(Config) ->
  call_add_signing_key(Config, [<<"mykey-1">>, <<"some key 1">>]),
  NewKeys = #{<<"key-2">> => <<"some key 2">>, <<"key-3">> => <<"some key 3">>},
  call_replace_signing_keys(Config, [NewKeys]),
  #{<<"key-2">> := <<"some key 2">>, <<"key-3">> := <<"some key 3">>} = call_get_signing_keys(Config, []).

replace_signing_keys_for_specific_resource_server(Config) ->
  ResourceServerId = <<"my-resource-server-3">>,
  #{<<"mykey-3-1">> := <<"some key 3-1">>} = call_add_signing_key(Config, [ResourceServerId, <<"mykey-3-1">>, <<"some key 3-1">>]),
  NewKeys = #{<<"key-2">> => <<"some key 2">>, <<"key-3">> => <<"some key 3">>},
  call_replace_signing_keys(Config, [ResourceServerId, NewKeys]),
  #{<<"key-2">> := <<"some key 2">>, <<"key-3">> := <<"some key 3">>} = call_get_signing_keys(Config, [ResourceServerId]).

get_root_resource_server_id_returns_error(_Config) ->
  {error, _} = rabbit_oauth2_config:get_root_resource_server_id().

get_root_resource_server_id(_Config) ->
  ?assertEqual(?RABBITMQ, rabbit_oauth2_config:get_root_resource_server_id()).

get_allowed_resource_server_ids_returns_empty_list(_Config) ->
  [] = rabbit_oauth2_config:get_allowed_resource_server_ids().

get_allowed_resource_server_ids_returns_resource_server_id(_Config) ->
  [?RABBITMQ] = rabbit_oauth2_config:get_allowed_resource_server_ids().

get_allowed_resource_server_ids_returns_all_resource_servers_ids(_Config) ->
  [ <<"rabbitmq1">>, <<"rabbitmq2">>, ?RABBITMQ] = rabbit_oauth2_config:get_allowed_resource_server_ids().

get_allowed_resource_server_ids_returns_resource_servers_ids(_Config) ->
  [<<"rabbitmq-0">>, <<"rabbitmq-1">>, <<"rabbitmq1">>, <<"rabbitmq2">> ] =
   lists:sort(rabbit_oauth2_config:get_allowed_resource_server_ids()).

index_resource_servers_by_id_else_by_key(_Config) ->
  {error, key_not_found} = rabbit_oauth2_config:find_audience_in_resource_server_ids(<<"0">>),
  {ok, <<"rabbitmq-0">>} = rabbit_oauth2_config:find_audience_in_resource_server_ids([<<"rabbitmq-0">>]),
  {ok, <<"rabbitmq-0">>} = rabbit_oauth2_config:find_audience_in_resource_server_ids(<<"rabbitmq-0">>).

find_audience_in_resource_server_ids_returns_key_not_found(_Config) ->
  {error, key_not_found} = rabbit_oauth2_config:find_audience_in_resource_server_ids(?RABBITMQ).

find_audience_in_resource_server_ids_returns_found_too_many(_Config) ->
  {error, only_one_resource_server_as_audience_found_many} = rabbit_oauth2_config:find_audience_in_resource_server_ids([?RABBITMQ, <<"rabbitmq1">>]).

find_audience_in_resource_server_ids_found_one_resource_servers(_Config) ->
  {ok, <<"rabbitmq1">>} = rabbit_oauth2_config:find_audience_in_resource_server_ids(<<"rabbitmq1">>),
  {ok, <<"rabbitmq1">>} = rabbit_oauth2_config:find_audience_in_resource_server_ids([<<"rabbitmq1">>, <<"other">>]).

find_audience_in_resource_server_ids_found_resource_server_id(_Config) ->
  {ok, ?RABBITMQ} = rabbit_oauth2_config:find_audience_in_resource_server_ids(?RABBITMQ),
  {ok, ?RABBITMQ} = rabbit_oauth2_config:find_audience_in_resource_server_ids([?RABBITMQ, <<"other">>]).

get_jwks_url_for_resource_server_id(_Config) ->
  ?assertEqual(<<"https://oauth-for-rabbitmq">>, rabbit_oauth2_config:get_jwks_url(?RABBITMQ)).

get_jwks_url_for_resource_servers_id(_Config) ->
  ?assertEqual(<<"https://oauth-for-rabbitmq1">>, rabbit_oauth2_config:get_jwks_url(<<"rabbitmq1">>)).

resolve_settings_via_inheritance(_Config) ->
  ?assertEqual(<<"https://oauth-for-rabbitmq">>, rabbit_oauth2_config:get_jwks_url(<<"rabbitmq-2">>)).

get_key_config(_Config) ->
  RootKeyConfig = rabbit_oauth2_config:get_key_config(<<"rabbitmq-2">>),
  ?assertEqual(<<"https://oauth-for-rabbitmq">>, proplists:get_value(jwks_url, RootKeyConfig)),

  KeyConfig = rabbit_oauth2_config:get_key_config(<<"rabbitmq1">>),
  ?assertEqual(<<"https://oauth-for-rabbitmq1">>, proplists:get_value(jwks_url, KeyConfig)).
