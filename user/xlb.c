#include <bpf.h>
#include <libbpf.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <asm/errno.h>
#include <linux/if_link.h>

#include "lb_consts.h"
#include "lb_structs.h"

static int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
	__u32 curr_prog_id;
	int err;

	err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err) {
		fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n",
			-err, strerror(-err));
		return -1;
	}

	if (!curr_prog_id)
		return 0;

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		fprintf(stderr, "ERR: %s() "
			"expected prog ID(%d) no match(%d), not removing\n",
			__func__, expected_prog_id, curr_prog_id);
		return -1;
	}

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
			__func__, err, strerror(-err));
		return -1;
	}

	return 0;
}

static int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
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
    unsigned int ifindex;
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
        fprintf(stderr, "Invalid input\n\n"
                "Usage: xlb <ifname> <ip_addr>...\n"
                "xlb adds server IP(s) to the bpf map for network load balancing.\n"
                "\n<ifname>  Network interface you load the XDP program on.\n"
                "<ip_addr>  IP addresses in integer (in host endian also).\n");
        exit(-1);
    }

    for (int i = 0; i < BUCKET_SIZE; i++) {
        /* TODO: hey! we have inet_pton() */
        ip[i] = atoi(argv[i + 2]);
        ip[i] = htonl(ip[i]);
    }

    ifindex = if_nametoindex(argv[1]); 
    if (!ifindex) {
/** TODO change to "Invalid ifname." */        fprintf(stderr, "Invalid interface name");
        exit(-1);
    }

    /**
     * At this stage, only HW mode requires ifindex, hence we use zero. If HW
     * mode is required, one should assign the ifindex to the field within
     * %xattr.
     * 
     * TODO: add XDP HW mode support.
     */
    err = bpf_prog_load_xattr(&xattr, &bpf_obj, &bpf_prog_fd);
    if (err) {
        fprintf(stderr, "Error loading bpf object file\n");
        exit(-1);
    }

    /**
     * Currently, we support only single program section within bpf object file.
     * 
     * TODO: add support for multi-prog bpf object
     */
    err = bpf_set_link_xdp_fd(ifindex, bpf_prog_fd, XDP_FLAGS_DRV_MODE);
    if (err < 0) {
        fprintf(stderr, "ERR: "
                "ifindex(%d) link set xdp fd failed (%d): %s\n",
                ifindex, -err, strerror(-err));
		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "XDP already loaded on device\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "XDP native mode not"
                    "supported on specified interface\n");
			break;
		default:
			break;
		}
		exit(-1);
    }

    bpf_map_fd = find_map_fd(bpf_obj, XDP_MAP_NAME);
    if (find_map_fd < 0) {
        xdp_link_detach(ifindex, XDP_FLAGS_DRV_MODE, 0);
        fprintf(stderr, "Error finding map fd\n");
        exit(-1);
    }

    for (unsigned int i = 0; i < BUCKET_SIZE; i++) {
        real.addr = ip[i];
        memcpy(real.mac, &mac[i][0], ETH_MAC_LEN);
        if (bpf_map_update_elem(bpf_map_fd, &i, &real, 0) < 0) {
            fprintf(stderr, "Error updating bpf map");
            break;
        }
    }

    return 0;
}
