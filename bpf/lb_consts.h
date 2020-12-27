#ifndef _LB_CONSTS_H
#define _LB_CONSTS_H

/* ipv4 protocol code in BE. then we dont need hton */
#define BE_ETH_P_IP 8

#define HASH_SEED 0xcafebabe
#define FOUR_TUPLE_SIZE 12

/* max num of reals */
#define BUCKET_SIZE 3

#define ETH_MAC_LEN 6

#define XDP_PROG_FILE_NAME "lb_kern.o"
#define XDP_MAP_NAME "reals"

#endif // _LB_CONSTS_H