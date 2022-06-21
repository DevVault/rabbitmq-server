-module(rabbit_mc_amqp_legacy).
-behaviour(mc).

-include_lib("rabbit_common/include/rabbit_framing.hrl").
-include_lib("amqp10_common/include/amqp10_framing.hrl").
-include_lib("rabbit_common/include/rabbit.hrl").
-include("mc.hrl").

-export([
         init/1,
         init_amqp/1,
         size/1,
         header/2,
         get_property/2,
         set_property/3,
         convert/2,
         protocol_state/3,
         serialize/2,
         message/3,
         message/4,
         message/5,
         from_basic_message/1
        ]).

-define(HEADER_GUESS_SIZE, 100). %% see determine_persist_to/2

-opaque state() :: #content{}.

-export_type([
              state/0
             ]).

%% mc implementation
init(#content{} = Content) ->
    %% TODO header routes
    {strip_header(Content, ?DELETED_HEADER), #{}}.

init_amqp(Sections) when is_list(Sections) ->
    {_H, MAnn, P, AProp, #'v1_0.data'{content = Payload}} =
        lists:foldl(
          fun
              (#'v1_0.header'{} = S, Acc) ->
                  setelement(1, Acc, S);
              (#'v1_0.message_annotations'{} = S, Acc) ->
                  setelement(2, Acc, S);
              (#'v1_0.properties'{} = S, Acc) ->
                  setelement(3, Acc, S);
              (#'v1_0.application_properties'{} = S, Acc) ->
                  setelement(4, Acc, S);
              (#'v1_0.data'{} = S, Acc) ->
                  setelement(5, Acc, S);
              (undefined, Acc) ->
                  Acc
          end, {undefined, undefined, undefined, undefined, undefined},
          Sections),

    %% TODO: header

    #'v1_0.properties'{message_id = MsgId,
                       user_id = UserId,
                       reply_to = ReplyTo0,
                       correlation_id = CorrId,
                       content_type = ContentType,
                       content_encoding = ContentEncoding,
                       creation_time = Timestamp} = case P of
                                                        undefined ->
                                                            #'v1_0.properties'{};
                                                        _ ->
                                                            P
                                                    end,

    AP0 = case AProp of
              #'v1_0.application_properties'{content = AC} -> AC;
              _ -> []
          end,
    MA0 = case MAnn of
              #'v1_0.message_annotations'{content = MC} -> MC;
              _ -> []
          end,

    {Type, AP1} = amqp10_map_get(utf8(<<"x-basic-type">>), AP0),
    {AppId, AP} = amqp10_map_get(utf8(<<"x-basic-app-id">>), AP1),

    {Priority, MA1} = amqp10_map_get(symbol(<<"x-basic-priority">>), MA0),
    {DelMode, MA2} = amqp10_map_get(symbol(<<"x-basic-delivery-mode">>), MA1),
    {Expiration, _MA} = amqp10_map_get(symbol(<<"x-basic-expiration">>), MA2),

    Headers0 = [to_091(unwrap(K), V) || {K, V} <- AP],
    {Headers1, MsgId091} = message_id(MsgId, <<"x-message-id-type">>, Headers0),
    {Headers, CorrId091} = message_id(CorrId, <<"x-correlation-id-type">>, Headers1),

    BP = #'P_basic'{message_id =  MsgId091,
                    delivery_mode = DelMode,
                    expiration = Expiration,
                    user_id = unwrap(UserId),
                    headers = case Headers of
                                  [] -> undefined;
                                  _ -> Headers
                              end,
                    reply_to = unwrap(ReplyTo0),
                    type = Type,
                    app_id = AppId,
                    priority = Priority,
                    correlation_id = CorrId091,
                    content_type = unwrap(ContentType),
                    content_encoding = unwrap(ContentEncoding),
                    timestamp = case unwrap(Timestamp) of
                                    undefined ->
                                        undefined;
                                    Ts ->
                                        Ts div 1000
                                end
                   },

    #content{class_id = 60,
             properties = BP,
             properties_bin = none,
             payload_fragments_rev = [Payload]}.


size(#content{properties_bin = PropsBin,
              properties = Props,
              payload_fragments_rev = Payload}) ->
    MetaSize = case is_binary(PropsBin) of
                   true ->
                       byte_size(PropsBin);
                   false ->
                       #'P_basic'{headers = Hs} = Props,
                       case Hs of
                           undefined -> 0;
                           _ -> length(Hs)
                       end * ?HEADER_GUESS_SIZE
               end,
    {MetaSize, iolist_size(Payload)}.

header(_Key, #content{properties = #'P_basic'{headers = undefined}} = C) ->
    {undefined, C};
header(Key, #content{properties = #'P_basic'{headers = Headers}} = C) ->
    case rabbit_misc:table_lookup(Headers, Key) of
        undefined ->
            {undefined, C};
        {_Type, Value} ->
            {Value, C}
    end.

get_property(durable,
             #content{properties = #'P_basic'{delivery_mode = Mode}} = C) ->
    {Mode == 2, C};
get_property(ttl, #content{properties = Props} = C) ->
    {ok, MsgTTL} = rabbit_basic:parse_expiration(Props),
    {MsgTTL, C};
get_property(priority, #content{properties = #'P_basic'{priority = P}} = C) ->
    {P, C};
get_property(timestamp, #content{properties = Props} = C) ->
    #'P_basic'{timestamp = Timestamp} = Props,
    case Timestamp of
        undefined ->
            {undefined, C};
        _ ->
            %% timestamp should be in ms
            {Timestamp * 1000, C}
    end;
get_property(_P, C) ->
    {undefined, C}.

set_property(ttl, undefined, #content{properties = Props} = C) ->
    %% TODO: impl rest, just what is needed for dead lettering for now
    C#content{properties = Props#'P_basic'{expiration = undefined}};
set_property(_P, _V, Msg) ->
    %% TODO: impl at least ttl set (needed for dead lettering)
    Msg.

convert(?MODULE, C) ->
    C;
convert(rabbit_mc_amqp, #content{properties = Props,
                                 payload_fragments_rev = Payload}) ->
    #'P_basic'{message_id = MsgId,
               expiration = Expiration,
               delivery_mode = DelMode,
               headers = Headers,
               user_id = UserId,
               reply_to = ReplyTo,
               type = Type,
               priority = Priority,
               app_id = AppId,
               correlation_id = CorrId,
               content_type = ContentType,
               content_encoding = ContentEncoding,
               timestamp = Timestamp } = Props,
    ConvertedTs = case Timestamp of
                      undefined ->
                          undefined;
                      _ ->
                          Timestamp * 1000
                  end,
    P = #'v1_0.properties'{message_id = wrap(utf8, MsgId),
                           user_id = wrap(binary, UserId),
                           to = undefined,
                           % subject = wrap(utf8, RKey),
                           reply_to = wrap(utf8, ReplyTo),
                           correlation_id = wrap(utf8, CorrId),
                           content_type = wrap(symbol, ContentType),
                           content_encoding = wrap(symbol, ContentEncoding),
                           creation_time = wrap(timestamp, ConvertedTs)},

    %% headers are stored as application properties when possible
    APC0 = [{wrap(utf8, K), from_091(T, V)}
            || {K, T, V}
               <- case Headers of
                      undefined -> [];
                      _ -> Headers
                  end,
               not unsupported_header_value_type(T)],
    %% properties that aren't used by the broker and
    %% do not map directly to AMQP 1.0 properties are stored
    %% in application properties
    APC = map_add(utf8, <<"x-basic-type">>, utf8, Type,
                  map_add(utf8, <<"x-basic-app-id">>, utf8, AppId, APC0)),

    %% properties that _are_ potentially used by the broker
    %% are stored as message annotations
    %% an alternative woud be to store priority and delivery mode in
    %% the amqp (1.0) header section using the dura
    MAC = map_add(symbol, <<"x-basic-priority">>, ubyte, Priority,
                  map_add(symbol, <<"x-basic-delivery-mode">>, ubyte, DelMode,
                          map_add(symbol, <<"x-basic-expiration">>, utf8, Expiration, []))),

    AP = #'v1_0.application_properties'{content = APC},
    MA = #'v1_0.message_annotations'{content = MAC},
    rabbit_mc_amqp:init_amqp([P, AP, MA,
                              #'v1_0.data'{content = lists:reverse(Payload)}]);
convert(_, _C) ->
    not_implemented.

protocol_state(#content{properties = #'P_basic'{headers = H00} = B} = C,
               Anns, Deaths) ->
    %% Add any x- annotations as headers
    %% TODO: conversion is very primitive for now
    H0 = case H00 of
             undefined -> [];
             _ ->
                 H00
         end,
    Headers0 = maps:fold(
                 fun (<<"x-", _/binary>> = Key, Val, H) when is_integer(Val) ->
                         [{Key, long, Val} | H];
                     (<<"x-", _/binary>> = Key, Val, H) when is_binary(Val) ->
                         [{Key, longstr, Val} | H];
                     (_, _, Acc) ->
                         Acc
                 end, deaths_to_headers(Deaths, H0), Anns),
    Headers = case Headers0 of
                  [] ->
                      undefined;
                  _ ->
                      Headers0
              end,

    C#content{properties = B#'P_basic'{headers = Headers},
              properties_bin = none}.

serialize(_C, _Anns) ->
    [].

-spec message(rabbit_types:exchange_name(), binary(), #content{}) -> mc:state().
message(ExchangeName, RoutingKey, Content) ->
    message(ExchangeName, RoutingKey, Content, #{}).

-spec message(rabbit_types:exchange_name(), binary(), #content{}, map()) ->
    mc:state() | rabbit_types:message().
message(XName, RoutingKey, Content, Anns) ->
    message(XName, RoutingKey, Content, Anns,
            rabbit_feature_flags:is_enabled(message_containers)).

%% helper for creating message container from messages received from
%% AMQP legacy
message(#resource{name = ExchangeNameBin}, RoutingKey,
        #content{properties = Props} = Content, Anns, true)
  when is_binary(RoutingKey) andalso
       is_map(Anns) ->
            HeaderRoutes = rabbit_basic:header_routes(Props#'P_basic'.headers),
            mc:init(?MODULE,
                    rabbit_basic:strip_bcc_header(Content),
                    Anns#{routing_keys => [RoutingKey | HeaderRoutes],
                          exchange => ExchangeNameBin});
message(#resource{} = XName, RoutingKey,
        #content{} = Content, Anns, false) ->
    {ok, Msg} = rabbit_basic:message(XName, RoutingKey, Content),
    case Anns of
        #{id := Id} ->
            Msg#basic_message{id = Id};
        _ ->
            Msg
    end.

from_basic_message(#basic_message{content = Content,
                                  id = Id,
                                  exchange_name = Ex,
                                  routing_keys = [RKey | _]}) ->
    Anns = case Id of
               undefined ->
                   #{};
               _ ->
                   #{id => Id}
           end,
    message(Ex, RKey, Content, Anns, true).

%% Internal

deaths_to_headers(undefined, Headers) ->
    Headers;
deaths_to_headers(#deaths{first = {FirstQueue, FirstReason} = FirstKey,
                          records = Records},
                  Headers0) ->
    #death{exchange = FirstEx} = maps:get(FirstKey, Records),
    Infos = maps:fold(
              fun ({QName, Reason}, #death{timestamp = Ts,
                                           exchange = Ex,
                                           count = Count,
                                           ttl = Ttl,
                                           routing_keys = RoutingKeys},
                   Acc) ->
                      %% The first routing key is the one specified in the
                      %% basic.publish; all others are CC or BCC keys.
                      RKs  = [hd(RoutingKeys) | rabbit_basic:header_routes(Headers0)],
                      RKeys = [{longstr, Key} || Key <- RKs],
                      ReasonBin = atom_to_binary(Reason, utf8),
                      PerMsgTTL = case Ttl of
                                      undefined -> [];
                                      _ when is_integer(Ttl) ->
                                          Expiration = integer_to_binary(Ttl),
                                          [{<<"original-expiration">>, longstr,
                                            Expiration}]
                                  end,
                      [{table, [{<<"count">>, long, Count},
                                {<<"reason">>, longstr, ReasonBin},
                                {<<"queue">>, longstr, QName},
                                {<<"time">>, timestamp, Ts div 1000},
                                {<<"exchange">>, longstr, Ex},
                                {<<"routing-keys">>, array, RKeys}] ++ PerMsgTTL}
                       | Acc]
              end, [], Records),

    Headers = rabbit_misc:set_table_value(
                Headers0, <<"x-death">>, array, Infos),
    % Headers = rabbit_basic:prepend_table_header(
    %             <<"x-death">>, Infos, Headers0),
    [{<<"x-first-death-reason">>, longstr, atom_to_binary(FirstReason, utf8)},
     {<<"x-first-death-queue">>, longstr, FirstQueue},
     {<<"x-first-death-exchange">>, longstr, FirstEx}
     | Headers].



strip_header(#content{properties = #'P_basic'{headers = undefined}}
             = DecodedContent, _Key) ->
    DecodedContent;
strip_header(#content{properties = Props = #'P_basic'{headers = Headers}}
             = DecodedContent, Key) ->
    case lists:keysearch(Key, 1, Headers) of
        false          -> DecodedContent;
        {value, Found} -> Headers0 = lists:delete(Found, Headers),
                          rabbit_binary_generator:clear_encoded_content(
                            DecodedContent#content{
                              properties = Props#'P_basic'{
                                             headers = Headers0}})
    end.

wrap(_Type, undefined) ->
    undefined;
wrap(Type, Val) ->
    {Type, Val}.

% unwrap(undefined) ->
%     undefined;
% unwrap({_Type, V}) ->
%     V.

from_091(longstr, V) when is_binary(V) -> {utf8, V};
from_091(long, V) -> {long, V};
from_091(unsignedbyte, V) -> {ubyte, V};
from_091(short, V) -> {short, V};
from_091(unsignedshort, V) -> {ushort, V};
from_091(unsignedint, V) -> {uint, V};
from_091(signedint, V) -> {int, V};
from_091(double, V) -> {double, V};
from_091(float, V) -> {float, V};
from_091(bool, V) -> {boolean, V};
from_091(binary, V) -> {binary, V};
from_091(timestamp, V) -> {timestamp, V * 1000};
from_091(byte, V) -> {byte, V};
from_091(void, _V) -> null.

map_add(_T, _Key, _Type, undefined, Acc) ->
    Acc;
map_add(KeyType, Key, Type, Value, Acc) ->
    [{wrap(KeyType, Key), wrap(Type, Value)} | Acc].

 unsupported_header_value_type(array) ->
     true;
 unsupported_header_value_type(table) ->
     true;
 unsupported_header_value_type(_) ->
     false.


amqp10_map_get(K, AP0) ->
    case lists:keytake(K, 1, AP0) of
        false ->
            {undefined, AP0};
        {value, {_, V}, AP}  ->
            {unwrap(V), AP}
    end.

utf8(T) -> {utf8, T}.
symbol(T) -> {symbol, T}.

unwrap(undefined) ->
    undefined;
unwrap({_Type, V}) ->
    V.
to_091(Key, {utf8, V}) when is_binary(V) -> {Key, longstr, V};
to_091(Key, {long, V}) -> {Key, long, V};
to_091(Key, {byte, V}) -> {Key, byte, V};
to_091(Key, {ubyte, V}) -> {Key, unsignedbyte, V};
to_091(Key, {short, V}) -> {Key, short, V};
to_091(Key, {ushort, V}) -> {Key, unsignedshort, V};
to_091(Key, {uint, V}) -> {Key, unsignedint, V};
to_091(Key, {int, V}) -> {Key, signedint, V};
to_091(Key, {double, V}) -> {Key, double, V};
to_091(Key, {float, V}) -> {Key, float, V};
%% NB: header values can never be shortstr!
to_091(Key, {timestamp, V}) -> {Key, timestamp, V div 1000};
to_091(Key, {binary, V}) -> {Key, binary, V};
to_091(Key, {boolean, V}) -> {Key, bool, V};
to_091(Key, true) -> {Key, bool, true};
to_091(Key, false) -> {Key, bool, false};
%% TODO
to_091(Key, undefined) -> {Key, void, undefined};
to_091(Key, null) -> {Key, void, undefined}.

message_id({uuid, UUID}, HKey, H0) ->
    H = [{HKey, longstr, <<"uuid">>} | H0],
    {H, rabbit_data_coercion:to_binary(rabbit_guid:to_string(UUID))};
message_id({ulong, N}, HKey, H0) ->
    H = [{HKey, longstr, <<"ulong">>} | H0],
    {H, erlang:integer_to_binary(N)};
message_id({binary, B}, HKey, H0) ->
    E = base64:encode(B),
    case byte_size(E) > 256 of
        true ->
            K = binary:replace(HKey, <<"-type">>, <<>>),
            {[{K, longstr, B} | H0], undefined};
        false ->
            H = [{HKey, longstr, <<"binary">>} | H0],
            {H, E}
    end;
message_id({utf8, S}, HKey, H0) ->
    case byte_size(S) > 256 of
        true ->
            K = binary:replace(HKey, <<"-type">>, <<>>),
            {[{K, longstr, S} | H0], undefined};
        false ->
            {H0, S}
    end;
message_id(MsgId, _, H) ->
    {H, unwrap(MsgId)}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
