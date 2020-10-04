#include <bpf.h>
#include <libbpf.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>

#include "lb_consts.h"
#include "lb_structs.h"

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "Error finding map by name: %s\n", mapname);
        exit(-1);
 	}

	map_fd = bpf_map__fd(map);

	return map_fd;
}

int main(int argc, char **argv)
{
    unsigned int ip[BUCKET_SIZE];
    unsigned int iface;
	int bpf_map_fd;
    int bpf_prog_fd = -1;
    int err;
	struct bpf_object *bpf_obj;
    struct reals real;
    struct bpf_prog_load_attr xattr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = XDP_PROG_FILE_NAME,
    };

    /* TODO: yes, this is... */
    unsigned char mac[BUCKET_SIZE][6] = {{0x52,0x54,0xa3,0x5c,0x2d,0x49},
                                         {0x52,0x54,0x25,0xd2,0xa1,0xf3},
                                         {0x52,0x54,0x2b,0xe7,0xa2,0x4c},};

    /* poor validation. Currently, one should fit all at once */
    if (argc < 2) {
        puts("Invalid input.\n\n"
             "Usage: xlb <ifname> <ip_addr>\n"
             "xlb adds server IP(s) to the bpf map for network load balancing.\n"
             "\n<ifname>  Network interface you load the XDP program on.\n"
             "<ip_addr>  IP address in integer (in host endian also).");
        exit(-1);
    }

    for (int i = 0; i < BUCKET_SIZE; i++) {
        ip[i] = atoi(argv[i + 2]);
        ip[i] = htonl(ip[i]);
    }

    iface = if_nametoindex(argv[1]);
    if (!iface) {
        puts("Invalid interface name");
        exit(-1);
    }

    xattr.ifindex = iface;
    err = bpf_prog_load_xattr(&xattr, &bpf_obj, &bpf_prog_fd);
    if (err) {
        puts("Error loading XDP prog obj");
        exit(-1);
    }
    bpf_map_fd = find_map_fd(bpf_obj, XDP_MAP_NAME);
    if (bpf_map_fd < 0) {
        puts("Error loading bpf map");
        exit(-1);
    }

    for (unsigned int i = 0; i < BUCKET_SIZE; i++) {
        real.addr = ip[i];
        memcpy(real.mac, &mac[i][0], ETH_MAC_LEN);
        if (bpf_map_update_elem(bpf_map_fd, &i, &real, 0) < 0) {
            puts("Error updating bpf map");
            break;
        }
    }

    return 0;
}
