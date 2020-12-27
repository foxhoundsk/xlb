#include <bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "lb_consts.h"
#include "lb_maps.h"
#include "lb_structs.h"
#include "murmur_hash.h"

static __always_inline bool parse_tcp(struct pkt_desc *pkt_meta,
									  void *data,
									  void *data_end)
{
	struct tcphdr *tcp = (struct tcphdr*) (data + sizeof(struct iphdr));

	if (tcp + 1 > data_end)
		return false;

	pkt_meta->keys.sport = tcp->source;
	pkt_meta->keys.dport = tcp->dest;

	return true;
}

static __always_inline struct reals *dst_lookup(struct pkt_desc *pkt_meta)
{
	__u32 digest;
	struct reals *real;

	digest = murmurhash((char *) &pkt_meta->keys, HASH_SEED) % BUCKET_SIZE;
	/* TODO: LRU lookup can perform here */

	real = bpf_map_lookup_elem(&reals, &digest);

	return real;
}

/* FB's impl of ipv4 checksum calculation,
 * somehow the following is not working, 
 * the verifier says that I have <<= pointer
 * arithmetic, maybe it's caused by -O2
 * compiler flag.
 * 
 * 	iph_csum =  (__u16 *) &iph;
 *	#pragma clang loop unroll(full)
 *	for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
 *		csum += *iph_csum++;
 *	iph->check = ~((csum & 0xffff) + (csum >> 16));
 * 
 * where csum is of type __u32
 * */
static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i ++) {
		if (csum >> 16)
		csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline void ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (int i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += *next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static __always_inline bool decap_ipip(struct xdp_md *ctx)
{
	struct ethhdr *new_eth, *old_eth;
	struct iphdr *outter_iph, *inner_iph;
	struct tcphdr *tcp;
	__u64 csum = 0;
//	__u16 old_addr;

	outter_iph = ((void *)(long) ctx->data) + sizeof(struct ethhdr);
	inner_iph = outter_iph + 1;
	tcp = (struct tcphdr *)(inner_iph + 1);
	if (outter_iph + 1 > (void *)(long)ctx->data_end ||
		inner_iph + 1 > (void *)(long)ctx->data_end ||
		tcp + 1 > (void *)(long)ctx->data_end) {
		return false;
	}

	if (!--inner_iph->ttl) {
		return false;
	}

//	old_addr = inner_iph->daddr;
//	inner_iph->daddr = outter_iph->daddr;

	inner_iph->check = 0; /* reset before recal. of csum */
//	tcp->check = 0; non-full cal (e.g. only daddr is changed) doesnt need this,
//	hence comment out
	ipv4_csum_inline(inner_iph, &csum);
	inner_iph->check = csum;

	/**
	 * tcp csum cal. (required if some fields of ip_hdr changed)
	 * Note that the following is only applicable for only daddr
	 * is changed
	 */
//	csum = 0;
//	csum = old_addr + (~bpf_ntohs(*(unsigned short *)&inner_iph->daddr) & 0xffff);
//  csum += bpf_ntohs(tcp->check);
//  csum = (csum & 0xffff) + (csum >> 16);
//  tcp->check = bpf_htons(csum + (csum >> 16) - 1);

	new_eth = ((void *)(long) ctx->data) + sizeof(struct iphdr);
	old_eth = (void *)(long) ctx->data;
	if (new_eth + 1 > (void *)(long)ctx->data_end ||
		old_eth + 1 > (void *)(long)ctx->data_end) {
			return false;
	}
	memcpy(new_eth->h_dest, old_eth->h_dest, ETH_MAC_LEN);
	memcpy(new_eth->h_source, old_eth->h_source, ETH_MAC_LEN);
	new_eth->h_proto = BE_ETH_P_IP;

	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct iphdr))) {
    	return false;
	}
	void *data = (void *)(long) ctx->data;
	void *data_end = (void *)(long) ctx->data_end;
	new_eth = data;
	if (new_eth + 1 > data_end) {
		return false;
	}

	return true;
}

static __always_inline bool encap_iph(struct reals *real,
								      struct pkt_desc *pkt_meta,
									  void *data, void *data_end)
{
	struct ethhdr *new_eth, *old_eth;
	struct iphdr *iph;
	__u64 csum = 0;

	/* update eth header first, since we are going to overwrite */
	new_eth = data;
	old_eth = data + sizeof(struct iphdr);
	iph = data + sizeof(struct ethhdr);
	if (new_eth + 1 > data_end || old_eth + 1 > data_end || iph + 1 > data_end)
		return false;

	memcpy(new_eth->h_source, old_eth->h_dest, ETH_MAC_LEN);
	memcpy(new_eth->h_dest, real->mac, ETH_MAC_LEN);
	new_eth->h_proto = BE_ETH_P_IP;

	iph->version = 4; /* ipv4 */
	iph->ihl = 5; /* no options set */
	iph->frag_off = 0;
	iph->protocol = IPPROTO_IPIP; /* outter-most iphdr */
	iph->check = 0;
	iph->tos = 0;
	iph->tot_len = bpf_htons(pkt_meta->size + sizeof(struct iphdr));
	iph->daddr = real->addr;
	iph->saddr = pkt_meta->daddr;
	iph->ttl = 64;

	/* chksum calc */
	ipv4_csum_inline(iph, &csum);
	iph->check = csum;

	return true;
}

static __always_inline int process_packet(struct xdp_md *ctx,
										  void *data, void *data_end)
{
	struct pkt_desc pkt_meta;
	struct reals *real;
	struct iphdr *iphdr = data + sizeof(struct ethhdr);

	/*
	 * something is wrong here, if one try to encap ip header processing
	 * within a function, it simply wont pass the verifier's validation.
	 * the function looks like:
	 * 
	 * static inline bool process_l3_header(struct pkt_desc *pkt_meta,
	 *								 void *data, void *data_end)
	 *	{
	 *		struct iphdr *iphdr = data + sizeof(struct ethhdr);
	 *
	 *		if (iphdr + 1 > data_end)
	 *			return false;
	 *
	 *		...following are the same except pointer manipulations
	 *
	 * with above, the verifier says:
	 *     R3 pointer arithmetic on pkt_end prohibited
	 * 
	 * any idea?
	 */
	if (iphdr + 1 > data_end)
		return XDP_DROP;

	if (iphdr->protocol != IPPROTO_TCP) {
		if (iphdr->protocol == IPPROTO_IPIP) {
			if (decap_ipip(ctx)) {
				return XDP_PASS;
			}
			else {
				return XDP_DROP;
			}
		}
	}

	if (!parse_tcp(&pkt_meta, iphdr, data_end))
		return XDP_DROP;

	pkt_meta.keys.src = iphdr->saddr;
	pkt_meta.keys.dst = iphdr->daddr;
	if (iphdr->ihl != 5)
		return XDP_PASS; /* packet has ip options inside, which we dont support */
	pkt_meta.size = bpf_ntohs(iphdr->tot_len);
	pkt_meta.proto = iphdr->protocol;
	pkt_meta.daddr = iphdr->daddr;

	real = dst_lookup(&pkt_meta);
	if (!real)
		return XDP_DROP;

	if (real->addr == iphdr->daddr) {
		return XDP_PASS;
	}

	/* expend the packet for ipip header */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct iphdr)))
		return XDP_DROP;
	data = (void *)(long) ctx->data;
	data_end = (void *)(long) ctx->data_end;

	if (!encap_iph(real, &pkt_meta, data, data_end))
		return XDP_DROP;

	return XDP_TX;
}

SEC("xdp")
int xlb_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
  	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
		return XDP_DROP;

	if (eth->h_proto == BE_ETH_P_IP) {
		return process_packet(ctx, data, data_end);
	}

	// packets except IPv4 passed to kernel
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
