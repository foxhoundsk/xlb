**UNDER DEVELOPMENT**

# XLB - XDP Load balancer

XLB only supports for IPv4 traffic currently.

## Build
Simply use `make` to build both control plane and data plane program.

## TODOs
- LRU for faster routing decision
- IPv6 support
- Better routing decision algorithm (we use modulo devision currently)
