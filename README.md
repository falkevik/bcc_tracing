# bcc_tracing
BCC tracing of pids allocations in the Beam

$ sudo ./erl_trace.py -bp /home/jonas/src/otp/bin/x86_64-unknown-linux-gnu/beam.smp -fs 20000
[sudo] password for jonas:
Exit with ctrl-c
pid <0.101.0> 302233599
pid <0.103.0> 302233599
pid <0.105.0> 302233599

$ ./bin/erl
Erlang/OTP 23 [RELEASE CANDIDATE 1] [erts-10.7.1] [source-0f87bed9fa] [64-bit] [smp:8:8] [ds:8:8:10] [async-threads:1] [hipe]

Eshell V10.7.1  (abort with ^G)
10> spawn(fun() -> prim_file:read_file("/home/jonas/Downloads/bigfile") end).
<0.101.0>
11> spawn(fun() -> prim_file:read_file("/home/jonas/Downloads/bigfile") end).
<0.103.0>
12> spawn(fun() -> prim_file:read_file("/home/jonas/Downloads/bigfile") end).
<0.105.0>
13>
