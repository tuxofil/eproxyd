#!/usr/bin/env escript

main(_) ->
    {ok, SS} = gen_tcp:listen(1080, [binary, {reuseaddr, true}]),
    main_loop(SS).

main_loop(SS) ->
    {ok, S} = gen_tcp:accept(SS),
    Pid = spawn(fun() -> receive ready -> conn_init(S) end end),
    ok = gen_tcp:controlling_process(S, Pid),
    Pid ! ready,
    main_loop(SS).

conn_init(S) ->
    {ok, {PeerAddr, PeerPort}} = inet:peername(S),
    ok = inet:setopts(S, [{active, once}]),
    receive
        {tcp, S, <<4:8/unsigned, 1:8/unsigned, Port:16/big-unsigned, A, B, C, D, _ID/binary>>} ->
            IP = {A, B, C, D},
            case is_private(IP) of
                true ->
                    ok = gen_tcp:send(S, <<0, 16#5b, 0:16/big-unsigned, 0:32/big-unsigned>>);
                false ->
                    ok = io:format("~w from ~w:~w to ~w:~w~n", [calendar:local_time(), PeerAddr, PeerPort, IP, Port]),
                    {ok, TS} = gen_tcp:connect(IP, Port, [{active, true}, binary]),
                    ok = gen_tcp:send(S, <<0, 16#5a, 0:16/big-unsigned, 0:32/big-unsigned>>),
                    ok = inet:setopts(S, [{active, true}]),
                    conn_loop(S, TS)
            end
    end.

conn_loop(S, TS) ->
    receive
        {tcp, S, Data} ->
            ok = gen_tcp:send(TS, Data),
            conn_loop(S, TS);
        {tcp, TS, Data} ->
            ok = gen_tcp:send(S, Data),
            conn_loop(S, TS);
        {tcp_closed, _Socket} ->
            ok;
        {tcp_error, _Socket, _Reason} ->
            ok
    end.

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
