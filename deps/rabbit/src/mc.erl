-module(mc).

-export([
         init/3,
         size/1,
         is/1,
         get_annotation/2,
         set_annotation/3,
         %% properties
         is_persistent/1,
         ttl/1,
         timestamp/1,
         priority/1,
         set_ttl/2,
         proto_header/2,
         %%
         convert/2,
         protocol_state/1,
         serialize/1,
         prepare/1,
         record_death/3,
         is_death_cycle/2,
         % deaths/1,
         last_death/1,
         death_queue_names/1
         ]).

% -define(NIL, []).
-include("mc.hrl").
-include_lib("amqp10_common/include/amqp10_framing.hrl").

-type str() :: atom() | string() | binary().

-type ann_key() :: str().
-type ann_value() :: str() | integer() | float() | [ann_value()].
-type protocol() :: module().
-type annotations() :: #{ann_key() => ann_value()}.

-type amqp_message_section() ::
    #'v1_0.header'{} |
    #'v1_0.delivery_annotations'{} |
    #'v1_0.message_annotations'{} |
    #'v1_0.properties'{} |
    #'v1_0.application_properties'{} |
    #'v1_0.data'{} |
    #'v1_0.amqp_sequence'{} |
    #'v1_0.amqp_value'{} |
    #'v1_0.footer'{}.


%% the protocol module must implement the mc behaviour
-record(?MODULE, {protocol :: module(),
                  %% protocol specific data term
                  data :: term(),
                  %% any annotations done by the broker itself
                  %% such as recording the exchange / routing keys used
                  annotations = #{} :: annotations(),
                  deaths :: undefined | #deaths{}
                 }).

-opaque state() :: #?MODULE{} | mc_compat:state().

-export_type([
              state/0,
              amqp_message_section/0,
              ann_key/0,
              ann_value/0
              ]).

-type proto_state() :: term().
-type property() :: user_id |
                    reply_to |
                    correlation_id |
                    message_id |
                    ttl |
                    priority |
                    durable |
                    timestamp
                    . %% etc
-type property_value() :: undefined |
                          string() |
                          binary() |
                          integer() |
                          float() |
                          boolean().

%% behaviour callbacks for protocol specific implementation
%% returns a map of additional annotations to merge into the
%% protocol generic annotations map
-callback init(term()) ->
    {proto_state(), annotations()}.

-callback init_amqp([amqp_message_section()]) -> proto_state().

-callback size(proto_state()) ->
    {MetadataSize :: non_neg_integer(),
     PayloadSize :: non_neg_integer()}.

-callback header(property(), proto_state()) ->
    {property_value(), proto_state()}.

-callback get_property(property(), proto_state()) ->
    {property_value(), proto_state()}.

%% strictly speaking properties ought to be immutable
-callback set_property(property(), Value :: term(), proto_state()) ->
    proto_state().

%% all protocol must be able to convert to amqp (1.0)
-callback convert(protocol(), proto_state()) ->
    proto_state() | not_supported.

%% emit a protocol specific state package
-callback protocol_state(proto_state(), annotations(),
                         undefined | #deaths{}) ->
    term().

%% serialize the data into the protocol's binary format
-callback serialize(proto_state(), annotations()) ->
    iodata().

%%% API

-spec init(protocol(), term(), annotations()) -> state().
init(Proto, Data, Anns)
  when is_atom(Proto)
       andalso is_map(Anns) ->
    {ProtoData, AddAnns} = Proto:init(Data),
    #?MODULE{protocol = Proto,
             data = ProtoData,
             %% not sure what the precedence rule should be for annotations
             %% that are explicitly passed vs annotations that are recovered
             %% from the protocol parsing
             annotations = maps:merge(AddAnns, Anns)}.

-spec size(state()) ->
    {MetadataSize :: non_neg_integer(),
     PayloadSize :: non_neg_integer()}.
size(#?MODULE{protocol = Proto,
              data = Data}) ->
    Proto:size(Data);
size(BasicMsg) ->
    mc_compat:size(BasicMsg).

-spec is(state()) -> boolean().
is(#?MODULE{}) ->
    true;
is(Term) ->
    mc_compat:is(Term).


-spec get_annotation(ann_key(), state()) -> ann_value() | undefined.
get_annotation(Key, #?MODULE{annotations = Anns}) ->
    maps:get(Key, Anns, undefined);
get_annotation(Key, BasicMessage) ->
    mc_compat:get_annotation(Key, BasicMessage).

-spec set_annotation(ann_key(), ann_value(), state()) ->
    state().
set_annotation(Key, Value, #?MODULE{annotations = Anns} = State) ->
    State#?MODULE{annotations = maps:put(Key, Value, Anns)};
set_annotation(Key, Value, BasicMessage) ->
    mc_compat:set_annotation(Key, Value, BasicMessage).

-spec proto_header(Key :: binary(), state()) ->
    property_value() | undefined.
proto_header(Key, #?MODULE{protocol = Proto,
                           data = Data}) ->
    {Result, _} = Proto:header(Key, Data),
    Result;
proto_header(Key, BasicMsg) ->
    mc_compat:proto_header(Key, BasicMsg).

-spec is_persistent(state()) -> boolean().
is_persistent(#?MODULE{protocol = Proto,
                       data = Data}) ->
    {Result, _} = Proto:get_property(durable, Data),
    Result;
is_persistent(BasicMsg) ->
    mc_compat:is_persistent(BasicMsg).

-spec ttl(state()) -> undefined | non_neg_integer().
ttl(#?MODULE{protocol = Proto,
             data = Data}) ->
    {Result, _} = Proto:get_property(ttl, Data),
    Result;
ttl(BasicMsg) ->
    mc_compat:ttl(BasicMsg).


-spec timestamp(state()) -> undefined | non_neg_integer().
timestamp(#?MODULE{protocol = Proto,
                   data = Data}) ->
    {Result, _} = Proto:get_property(timestamp, Data),
    Result;
timestamp(BasicMsg) ->
    mc_compat:timestamp(BasicMsg).

-spec priority(state()) -> undefined | non_neg_integer().
priority(#?MODULE{protocol = Proto,
                   data = Data}) ->
    {Result, _} = Proto:get_property(priority, Data),
    Result;
priority(BasicMsg) ->
    mc_compat:priority(BasicMsg).

-spec set_ttl(undefined | non_neg_integer(), state()) -> state().
set_ttl(Value, #?MODULE{protocol = Proto,
                        data = Data} = State) ->
    State#?MODULE{data = Proto:set_property(ttl, Value, Data)};
set_ttl(Value, BasicMsg) ->
    mc_compat:set_ttl(Value, BasicMsg).

-spec convert(protocol(), state()) -> state().
convert(Proto, #?MODULE{protocol = Proto} = State) ->
    State;
convert(TargetProto, #?MODULE{protocol = Proto,
                              data = Data} = State) ->
    case Proto:convert(TargetProto, Data) of
        not_implemented ->
            %% convert to 1.0 then try again
            AmqpData = Proto:convert(rabbit_mc_amqp, Data),
            %% init the target from a list of amqp sections
            State#?MODULE{protocol = TargetProto,
                          data = TargetProto:init_amqp(AmqpData)};
        TargetState ->
            State#?MODULE{protocol = TargetProto,
                          data = TargetState}
    end;
convert(Proto, BasicMsg) ->
    mc_compat:convert(Proto, BasicMsg).

-spec protocol_state(state()) -> term().
protocol_state(#?MODULE{protocol = Proto,
                        annotations = Anns,
                        data = Data,
                        deaths = Deaths}) ->
    Proto:protocol_state(Data, Anns, Deaths);
protocol_state(BasicMsg) ->
    mc_compat:protocol_state(BasicMsg).

-spec prepare(state()) -> state().
prepare(State) ->
    State.

-spec record_death(rabbit_dead_letter:reason(),
                   SourceQueue :: binary(),
                   state()) -> state().
record_death(Reason, SourceQueue,
             #?MODULE{protocol = Mod,
                      data = Data,
                      annotations = Anns,
                      deaths = Ds0} = State) ->
    Key = {SourceQueue, Reason},
    Exchange = maps:get(exchange, Anns),
    RoutingKeys = maps:get(routing_keys, Anns),
    Timestamp = os:system_time(millisecond),
    case Ds0 of
        undefined ->
            {Ttl, _} = Mod:get_property(ttl, Data),
            Ds = #deaths{last = Key,
                         first = Key,
                         records = #{Key => #death{count = 1,
                                                   ttl = Ttl,
                                                   exchange = Exchange,
                                                   routing_keys = RoutingKeys,
                                                   timestamp = Timestamp}}},

            State#?MODULE{deaths = Ds};
        #deaths{records = Rs} ->
            Death = #death{count = C} = maps:get(Key, Rs,
                                                 #death{exchange = Exchange,
                                                        routing_keys = RoutingKeys,
                                                        timestamp = Timestamp}),
            Ds = Ds0#deaths{last = Key,
                            records = Rs#{Key => Death#death{count = C + 1}}},
            State#?MODULE{deaths = Ds}
    end;
record_death(Reason, SourceQueue, BasicMsg) ->
    mc_compat:record_death(Reason, SourceQueue, BasicMsg).


-spec is_death_cycle(binary(), state()) -> boolean().
is_death_cycle(TargetQueue, #?MODULE{deaths = Deaths}) ->
    is_cycle(TargetQueue, maps:keys(Deaths#deaths.records));
is_death_cycle(TargetQueue, BasicMsg) ->
    mc_compat:is_death_cycle(TargetQueue, BasicMsg).

-spec death_queue_names(state()) -> [binary()].
death_queue_names(#?MODULE{deaths = Deaths}) ->
    case Deaths of
        undefined ->
            [];
        #deaths{records = Records} ->
            [Q || {Q, _} <- maps:keys(Records)]
    end;
death_queue_names(BasicMsg) ->
    mc_compat:death_queue_names(BasicMsg).

% -spec deaths(state()) -> undefined | #deaths{}.
% deaths(#?MODULE{deaths = Deaths}) ->
%     Deaths.

-spec last_death(state()) ->
    undefined | {death_key(), #death{}}.
last_death(#?MODULE{deaths = undefined}) ->
    undefined;
last_death(#?MODULE{deaths = #deaths{last = Last,
                                     records = Rs}}) ->
    {Last, maps:get(Last, Rs)};
last_death(BasicMsg) ->
    mc_compat:last_death(BasicMsg).

-spec serialize(state()) -> iodata().
serialize(#?MODULE{protocol = Proto,
                   annotations = Anns,
                   data = Data}) ->
    Proto:serialize(Data, Anns).

%% INTERNAL

%% if there is a death with a source queue that is the same as the target
%% queue name and there are no newer deaths with the 'rejected' reason then
%% consider this a cycle
is_cycle(_Queue, []) ->
    false;
is_cycle(_Queue, [{_Q, rejected} | _]) ->
    %% any rejection breaks the cycle
    false;
is_cycle(Queue, [{Queue, Reason} | _])
  when Reason =/= rejected ->
    true;
is_cycle(Queue, [_ | Rem]) ->
    is_cycle(Queue, Rem).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.
