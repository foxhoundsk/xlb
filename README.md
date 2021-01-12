# XDP (eXpress Data Path) Playground
A playground for newbie to the XDP.

## Environment Setup
We use Clang as compiler for the eBPF, which requires at least `v3.4.0` in order to build eBPF program.

Note that [GCC also has support for eBPF since version 10](https://www.phoronix.com/scan.php?page=news_item&px=GCC-10-eBPF-Port-Lands).

First, create a virtual network environment for playing with the XDP safely:
```
$ sudo ./testenv.sh setup --name=play
```

Now, we have the following environment:
```
+-----------------------------+                          +-----------------------------+
| Root namespace              |                          | Testenv namespace 'play'    |
|                             |      From 'play'         |                             |
|                    +--------+ TX->                RX-> +--------+                    |
|                    | play +--------------------------+  veth0   |                    |
|                    +--------+ <-RX                <-TX +--------+                    |
|                             |       From 'veth0'       |                             |
+-----------------------------+                          +-----------------------------+
```
where the network namespace is in short a separated environment against the default network namespace, which contains your phy./virt. NIC. It allows you to do arrangement for the NICs or test network configurations safely and neatly.

Add an alias for convenient ops later:
```
$ alias t='sudo ip netns exec play'
```

## Packet Dropping
This lab hooks a XDP program which drops all of the incoming packets.

Assume you are under the root directory of the playground, run command:
```
$ make
```
to build the eBPF programs.

If all goes well, we have eBPF programs located at the root directory now.

`ping` the interface (`play` here) inside the root namespace to ensure that it works properly:
```
$ t ping fc00:dead:cafe:1::1
```

Run the following command to hook the eBPF packet dropping program onto the interface we just created:
```
$ sudo ip link set dev play xdp obj play.o sec drop
```

`ping` again, still replying?
```
$ t ping fc00:dead:cafe:1::1
```

If not, the eBPF program is now working, cheers!

## Packet Filtering
This lab hooks a XDP program which filters packet with odd sequence number within the ICMP header.

Run the following command to unload the previously loaded (if any) eBPF program:
```
$ sudo ip link set dev play xdp off
```

Hook the packet filtering program onto the interface:
```
$ sudo ip link set dev play xdp obj play.o sec filter
```

`ping` the interface, how is the reply going?

If you see only even seq. number `ping` replies, then we have managed to filter the odd ones.

## Tearing Down the Environment
Simply run:
```
$ sudo ./testenv.sh teardown; unalias t
```

You are now outside of the playground, see ya!

## XLB
Except `bpf/play.c`, `testenv.sh`, `config.sh` and `setup-env.sh`, the rest of the files are all XLB related sources. If one is interested in, `xlb_intro.md` contains its build instructions and usage. Enjoy your journey!