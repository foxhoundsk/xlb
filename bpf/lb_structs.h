#ifndef _LB_STRUCTS_H
#define _LB_STRUCTS_H

struct keys {
    __be32 src;
    __be32 dst;
    __be16 sport;
    __be16 dport;
};

struct pkt_desc {
    struct keys keys;
    __u32 daddr;
    __u16 size;
    __u8 proto;
};

struct reals {
    __u32 addr;
    __u8 mac[6];
};

#endif // _LB_STRUCTS_H