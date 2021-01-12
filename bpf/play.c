#include <bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

SEC("drop")
int xdp_drop(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("filter")
int xdp_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
  	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;
	struct icmp6hdr *icmp6hdr;

	if (eth + 1 > data_end)
		return XDP_DROP;
	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return XDP_PASS;
	
	ipv6 = data + sizeof(struct ethhdr);
	if (ipv6 + 1 > data_end)
		return XDP_DROP;
	if (ipv6->nexthdr != IPPROTO_ICMPV6)
		return XDP_PASS;

	icmp6hdr = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
	if (icmp6hdr + 1 > data_end)
		return XDP_DROP;
	
	if (bpf_ntohs(icmp6hdr->icmp6_sequence) & 1)
		return XDP_DROP;

	return XDP_PASS;
}