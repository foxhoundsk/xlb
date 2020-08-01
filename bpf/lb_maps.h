#ifndef _LB_MAPS_H
#define _LB_MAPS_H

#include <bpf_helpers.h>

#include "lb_consts.h"
#include "lb_structs.h"

struct bpf_map_def SEC("maps") reals = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct reals),
	.max_entries = BUCKET_SIZE,
};

#endif // _LB_CONSTS_H
