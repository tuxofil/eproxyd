#!/usr/bin/env escript

%% @doc
-spec main(Args :: [string()]) -> no_return().
main(_) ->
    {ok, ServerSocket} = gen_tcp:listen(1080, [binary, {reuseaddr, true}]),
    {ok, Sockname} = inet:sockname(ServerSocket),
    _ = put(id, "main-" ++ s2s(Sockname)),
    log("started", []),
    main_loop(ServerSocket).

%% proto types
-define(SOCKS4, 4).
-define(SOCKS5, 5).

%% commands
-define(CONNECT, 1).
-define(BIND, 2).

%% SOCKS5 authentication methods
-define(S5_NOAUTH, 0).

%% SOCKS5 address type
-define(S5_A_IPv4, 1).
-define(S5_A_DOMAIN, 3).
-define(S5_A_IPv6, 4).

%% @doc
-spec main_loop(ServerSocket :: gen_tcp:socket()) -> no_return().
main_loop(ServerSocket) ->
    {ok, ClientSocket} = gen_tcp:accept(ServerSocket),
    WorkerPid =
        spawn(
          fun() ->
                  receive
                      ready ->
                          {ok, Peer} = inet:peername(ClientSocket),
                          _ = put(id, s2s(Peer)),
                          ok = inet:setopts(ClientSocket, [{active, once}]),
                          receive
                              {tcp, ClientSocket, <<?SOCKS4, Request/binary>>} ->
                                  socks4_handshake(ClientSocket, Request);
                              {tcp, ClientSocket, <<?SOCKS5, Request/binary>>} ->
                                  socks5_handshake(ClientSocket, Request);
                              {tcp, ClientSocket, Unknown} ->
                                  log("unknown req: ~p", [Unknown])
                          after 2000 -> ok end
                  after 1000 -> ok end
          end),
    ok = gen_tcp:controlling_process(ClientSocket, WorkerPid),
    WorkerPid ! ready,
    main_loop(ServerSocket).

%% @doc
-spec socks4_handshake(ClientSocket :: gen_tcp:socket(), Request :: binary()) -> ok.
socks4_handshake(S, <<?CONNECT, Port:16/big-unsigned, A, B, C, D, _ID/binary>>) ->
    IP = {A, B, C, D},
    case is_private(IP) of
        true ->
            ok = gen_tcp:send(S, <<0, 16#5b, 0:16/big-unsigned, 0:32/big-unsigned>>);
        false ->
            {ok, TS} = gen_tcp:connect(IP, Port, [{active, true}, binary]),
            log("S4 connected to ~s", [s2s(IP, Port)]),
            ok = gen_tcp:send(S, <<0, 16#5a, 0:16/big-unsigned, 0:32/big-unsigned>>),
            ok = inet:setopts(S, [{active, true}]),
            conn_loop(S, TS)
    end;
socks4_handshake(S, <<?BIND, Port:16/big-unsigned, A, B, C, D, _ID/binary>>) ->
    IP = {A, B, C, D},
    log("S4 req bind to ~s - NOT IMPLEMENTED", [s2s(IP, Port)]),
    ok = gen_tcp:send(S, <<0, 16#5b, 0:16/big-unsigned, 0:32/big-unsigned>>).

%% @doc
-spec socks5_handshake(ClientSocket :: gen_tcp:socket(), Request :: binary()) -> ok.
socks5_handshake(S, <<Len, Tail/binary>>) ->
    {SupportedMethodsBin, _} = split_binary(Tail, Len),
    SupportedMethods = binary_to_list(SupportedMethodsBin),
    log("S5 supported methods: ~w", [SupportedMethods]),
    case lists:member(?S5_NOAUTH, SupportedMethods) of
        true ->
            ok = gen_tcp:send(S, <<?SOCKS5, ?S5_NOAUTH>>),
            ok = inet:setopts(S, [{active, once}]),
            receive
                {tcp, S, <<?SOCKS5, ?CONNECT, 0, Type, Req/binary>>} ->
                    TPeer = {IP, Port} = s5_decode_addr(Type, Req),
                    log("S5 req connect to ~s", [s2s(TPeer)]),
                    case is_private(IP) of
                        true ->
                            ok = gen_tcp:send(S, <<?SOCKS5, 2, 0, 1, 0, 0, 0, 0, 0:16/big-unsigned>>);
                        false ->
                            {ok, TS} = gen_tcp:connect(IP, Port, [{active, true}, binary]),
                            log("S5 connected to ~s", [s2s(TPeer)]),
                            ok = gen_tcp:send(S, <<?SOCKS5, 0, 0, 1, 0, 0, 0, 0, 0:16/big-unsigned>>),
                            ok = inet:setopts(S, [{active, true}]),
                            conn_loop(S, TS)
                    end;
                {tcp, S, Unknown} ->
                    log("S5 unknown request: ~p", [Unknown])
            end;
        false ->
            log("S5 inappropriate auth methods", []),
            ok = gen_tcp:send(S, <<?SOCKS5, 16#ff>>)
    end.

%% @doc
-spec s5_decode_addr(Type :: integer(), Data :: binary()) ->
                            {Address :: inet:ip_address() | binary(),
                             Port :: inet:port_number()}.
s5_decode_addr(?S5_A_IPv4, <<A, B, C, D, Port:16/big-unsigned>>) ->
    {{A, B, C, D}, Port};
%% Using a domain is a potential security hazard until
%% is_private/1 learns to recognize private network destinations
%% from such hostnames.
%%s5_decode_addr(?S5_A_DOMAIN, <<Len, Tail/binary>>) ->
%%    {Domain, <<Port:16/big-unsigned>>} = split_binary(Tail, Len),
%%    {Domain, Port};
s5_decode_addr(?S5_A_IPv6, <<A:16/big-unsigned, B:16/big-unsigned,
                             C:16/big-unsigned, D:16/big-unsigned,
                             E:16/big-unsigned, F:16/big-unsigned,
                             G:16/big-unsigned, H:16/big-unsigned,
                             Port:16/big-unsigned>>) ->
    {{A, B, C, D, E, F, G, H}, Port}.

%% @doc
-spec conn_loop(ClientSocket :: gen_tcp:socket(),
                TargetSocket :: gen_tcp:socket()) -> ok.
conn_loop(ClientSocket, TargetSocket) ->
    receive
        {tcp, ClientSocket, Data} ->
            ok = gen_tcp:send(TargetSocket, Data),
            conn_loop(ClientSocket, TargetSocket);
        {tcp, TargetSocket, Data} ->
            ok = gen_tcp:send(ClientSocket, Data),
            conn_loop(ClientSocket, TargetSocket);
        {tcp_closed, ClientSocket} ->
            log("client connection closed", []);
        {tcp_error, ClientSocket, Reason} ->
            log("client connection error: ~9999p", [Reason]);
        {tcp_closed, TargetSocket} ->
            log("target connection closed", []);
        {tcp_error, TargetSocket, Reason} ->
            log("target connection error: ~9999p", [Reason])
    end.

%% @doc
-spec is_private(inet:ip_address()) -> boolean().
is_private({192, 168, _, _}) ->
    true;
is_private({127, _, _, _}) ->
    true;
is_private({10, _, _, _}) ->
    true;
is_private({172, A, _, _}) when A >= 16, A =< 31 ->
    true;
is_private(_) ->
    false.

%% @doc
-spec log(Format :: string(), Args :: list()) -> ok.
log(Fmt, Args) ->
    ID = get(id),
    {{Y, M, D}, {H, Min, Sec}} = calendar:local_time(),
    io:format(
      "~4..0B-~2..0B-~2..0B ~2..0B:~2..0B:~2..0B ~s>> " ++ Fmt ++ "~n",
      [Y, M, D, H, Min, Sec, ID | Args]).

%% @doc
-spec a2s(inet:ip_address()) -> iolist().
a2s({A, B, C, D}) ->
    lists:flatten(io_lib:format("~w.~w.~w.~w", [A, B, C, D]));
a2s(Binary) when is_binary(Binary) ->
    Binary.

%% @doc
-spec s2s({inet:ip_address(), inet:port_number()}) -> iolist().
s2s({A, P}) ->
    s2s(A, P).

%% @doc
-spec s2s(inet:ip_address(), inet:port_number()) -> iolist().
s2s(A, P) ->
    lists:flatten(io_lib:format("~s:~w", [a2s(A), P])).
