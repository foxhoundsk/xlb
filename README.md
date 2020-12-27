# XLB - XDP Load Balancer
A Linux XDP based load balancer, which currently supports only IPv4 traffic.

## Prerequisite
- Add VIP to the loopback device
    E.g.:
    ```
    $ ip addr add 10.10.0.5/8 dev lo
    ```
    where `10.10.0.5` is the VIP.
- Configure ARP settings
    Possible configuration would be:
    ```
    $ sysctl net.ipv4.conf.all.arp_ignore=1
    $ sysctl net.ipv4.conf.eth0.arp_ignore=1
    $ sysctl net.ipv4.conf.all.arp_announce=2
    $ sysctl net.ipv4.conf.eth0.arp_announce=2
    ```
With these adjustments, the LB can do DSR (Direct Server Return) properly with VIP as source address of the response.

## Build
Since we use [libbpf](https://github.com/libbpf/libbpf) as our eBPF library, we need pull it first:
```
$ git submodule update --init
```
Then simply run `make` to build both control plane and data plane sources.

## TODOs
- LRU for faster routing decision
- IPv6 support
- Better routing decision algorithm (we're using modulo devision currently)
