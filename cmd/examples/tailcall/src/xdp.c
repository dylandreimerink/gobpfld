#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

/*
 * bpf_map_lookup_elem
 *
 * 	Perform a lookup in *map* for an entry associated to *key*.
 *
 * Returns
 * 	Map value associated to *key*, or **NULL** if no entry was
 * 	found.
 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

/*
 * bpf_map_update_elem
 *
 * 	Add or update the value of the entry associated to *key* in
 * 	*map* with *value*. *flags* is one of:
 *
 * 	**BPF_NOEXIST**
 * 		The entry for *key* must not exist in the map.
 * 	**BPF_EXIST**
 * 		The entry for *key* must already exist in the map.
 * 	**BPF_ANY**
 * 		No condition on the existence of the entry for *key*.
 *
 * 	Flag value **BPF_NOEXIST** cannot be used for maps of types
 * 	**BPF_MAP_TYPE_ARRAY** or **BPF_MAP_TYPE_PERCPU_ARRAY**  (all
 * 	elements always exist), the helper would return an error.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

/*
 * bpf_tail_call
 *
 * 	This special helper is used to trigger a "tail call", or in
 * 	other words, to jump into another eBPF program. The same stack
 * 	frame is used (but values on stack and in registers for the
 * 	caller are not accessible to the callee). This mechanism allows
 * 	for program chaining, either for raising the maximum number of
 * 	available eBPF instructions, or to execute given programs in
 * 	conditional blocks. For security reasons, there is an upper
 * 	limit to the number of successive tail calls that can be
 * 	performed.
 *
 * 	Upon call of this helper, the program attempts to jump into a
 * 	program referenced at index *index* in *prog_array_map*, a
 * 	special map of type **BPF_MAP_TYPE_PROG_ARRAY**, and passes
 * 	*ctx*, a pointer to the context.
 *
 * 	If the call succeeds, the kernel immediately runs the first
 * 	instruction of the new program. This is not a function call,
 * 	and it never returns to the previous program. If the call
 * 	fails, then the helper has no effect, and the caller continues
 * 	to run its subsequent instructions. A call can fail if the
 * 	destination program for the jump does not exist (i.e. *index*
 * 	is superior to the number of entries in *prog_array_map*), or
 * 	if the maximum number of tail calls has been reached for this
 * 	chain of programs. This limit is defined in the kernel by the
 * 	macro **MAX_TAIL_CALL_CNT** (not accessible to user space),
 * 	which is currently set to 32.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) 12;

/*
 * bpf_xdp_adjust_meta
 *
 * 	Adjust the address pointed by *xdp_md*\ **->data_meta** by
 * 	*delta* (which can be positive or negative). Note that this
 * 	operation modifies the address stored in *xdp_md*\ **->data**,
 * 	so the latter must be loaded only after the helper has been
 * 	called.
 *
 * 	The use of *xdp_md*\ **->data_meta** is optional and programs
 * 	are not required to use it. The rationale is that when the
 * 	packet is processed with XDP (e.g. as DoS filter), it is
 * 	possible to push further meta data along with it before passing
 * 	to the stack, and to give the guarantee that an ingress eBPF
 * 	program attached as a TC classifier on the same device can pick
 * 	this up for further post-processing. Since TC works with socket
 * 	buffers, it remains possible to set from XDP the **mark** or
 * 	**priority** pointers, or other pointers for the socket buffer.
 * 	Having this scratch space generic and programmable allows for
 * 	more flexibility as the user is free to store whatever meta
 * 	data they need.
 *
 * 	A call to this helper is susceptible to change the underlying
 * 	packet buffer. Therefore, at load time, all checks on pointers
 * 	previously done by the verifier are invalidated and must be
 * 	performed again, if the helper is used in combination with
 * 	direct packet access.
 *
 * Returns
 * 	0 on success, or a negative error in case of failure.
 */
static long (*bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = (void *) 54;

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

/*
 * This struct is stored in the XDP 'data_meta' area, which is located
 * just in-front-of the raw packet payload data.  The meaning is
 * specific to these two BPF programs that use it as a communication
 * channel.  XDP adjust/increase the area via a bpf-helper, and TC use
 * boundary checks to see if data have been provided.
 *
 * The struct must be 4 byte aligned, which here is enforced by the
 * struct __attribute__((aligned(4))).
 */
struct meta_info {
	__u32 nh_off;
} __attribute__((aligned(4)));

struct traffic_stats {
	__u64 pkts;
	__u64 bytes;
};

// Array holding references to all eBPF programs for tail-calls
struct bpf_map_def SEC("maps") tails = {
	.type 			= BPF_MAP_TYPE_PROG_ARRAY,
	.key_size 		= sizeof(__u32),
	.value_size 	= sizeof(__u32),
	.max_entries 	= 4, // We will only be using 4: ip, ipv6, tcp, and udp
};

#define PARSE_IPv4 0
#define PARSE_IPv6 1
#define PARSE_TCP 2
#define PARSE_UDP 3

// Stats on packets keyed by protocol number
struct bpf_map_def SEC("maps") ip_proto_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u8),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 16, // stats on top 16 protocol seem more than enough
	.map_flags 	 = BPF_F_NO_COMMON_LRU,
};

// Stats on udp packets keyed by dest port
struct bpf_map_def SEC("maps") udp_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u16),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 128, // top 128 udp ports seems good enough
	.map_flags   = BPF_F_NO_COMMON_LRU,
};

// Stats on tcp packets keyed by dest port
struct bpf_map_def SEC("maps") tcp_stats = {
	.type        = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size    = sizeof(__u16),
	.value_size  = sizeof(struct traffic_stats),
	.max_entries = 128, // top 128 tcp ports seems good enough
	.map_flags   = BPF_F_NO_COMMON_LRU,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __noinline void inc_ip_proto(
	__u8 proto,
	__u64 framesize
) {
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&ip_proto_stats, &proto);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
		bpf_map_update_elem(&ip_proto_stats, &proto, &stats, BPF_ANY);
	} else {
		stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}
}

SEC("xdp")
int tcp_prog(struct xdp_md* ctx) {
	void *data      = (void *)(unsigned long)ctx->data;
	void *data_end  = (void *)(unsigned long)ctx->data_end;
	
	/* Check data_meta have room for meta_info struct */
	struct meta_info* meta = (void *)(unsigned long)ctx->data_meta;
	if( meta + 1 > data ){
		return XDP_ABORTED;
	}

	// Since nh_off is used as offset into the packet the verifier doesn't
	// allow us to use meta->nh_off directly even if we check that 'data + meta->nh_off <= data' is true.
	// Because this switch will cause nh_offset to be 0 or one of the cases the verifier can check every
	// permutation to see that it is correct. (using inline assebly we can most likely add checks to meta->nh_off
	// which will then allow it to use a dynamic value between data and data_end but I have not yet figured
	// out how to do it via C.)
	__u32 nh_off;
	switch (meta->nh_off) {
		case sizeof(struct ethhdr) + sizeof(struct iphdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct ipv6hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6hdr);
		break;
	}

	struct tcphdr* tcphdr = data + nh_off;
	nh_off += sizeof(struct tcphdr);
	__u64 framesize = data_end - data;

	
	// If there is not enough data to parse a UDP header, drop the packet
	if( data + nh_off > data_end ) {
		return XDP_DROP;
	}

	__le16 le_dest = bpf_ntohs(tcphdr->dest);
	// Get existing stats
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&tcp_stats, &le_dest);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };
		bpf_map_update_elem(&tcp_stats, &le_dest, &stats, BPF_ANY);
	} else {
        stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}

	return XDP_PASS;
}

SEC("xdp")
int udp_prog(struct xdp_md* ctx) {
	void *data      = (void *)(unsigned long)ctx->data;
	void *data_end  = (void *)(unsigned long)ctx->data_end;
	
	/* Check data_meta have room for meta_info struct */
	struct meta_info* meta = (void *)(unsigned long)ctx->data_meta;
	if( meta + 1 > data ){
		return XDP_ABORTED;
	}

	// Since nh_off is used as offset into the packet the verifier doesn't
	// allow us to use meta->nh_off directly even if we check that 'data + meta->nh_off <= data' is true.
	// Because this switch will cause nh_offset to be 0 or one of the cases the verifier can check every
	// permutation to see that it is correct. (using inline assebly we can most likely add checks to meta->nh_off
	// which will then allow it to use a dynamic value between data and data_end but I have not yet figured
	// out how to do it via C.)
	__u32 nh_off;
	switch (meta->nh_off) {
		case sizeof(struct ethhdr) + sizeof(struct iphdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct iphdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct iphdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct ipv6hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr) + sizeof(struct ipv6hdr);
		break;
	}

	struct udphdr* udphdr = data + nh_off;
	nh_off += sizeof(struct udphdr);
	__u64 framesize = data_end - data;
	
	// If there is not enough data to parse a UDP header, drop the packet
	if( data + nh_off > data_end ) {
		return XDP_DROP;
	}

	__le16 le_dest = bpf_ntohs(udphdr->dest);
	// Get existing stats
	struct traffic_stats* stats_ptr = bpf_map_lookup_elem(&udp_stats, &le_dest);
	if( stats_ptr == NULL ) {
		// Make a new stats object
		struct traffic_stats stats = {
            .pkts = 1,
            .bytes = framesize,
        };

		bpf_map_update_elem(&udp_stats, &le_dest, &stats, BPF_ANY);
	} else {
		stats_ptr->pkts++;
        stats_ptr->bytes += framesize;
	}

	return XDP_PASS;
}

SEC("xdp")
int ipv4_prog(struct xdp_md* ctx) {
	void *data      = (void *)(unsigned long)ctx->data;
	void *data_end  = (void *)(unsigned long)ctx->data_end;
	
	/* Check data_meta have room for meta_info struct */
	struct meta_info* meta = (void *)(unsigned long)ctx->data_meta;
	if( meta + 1 > data ){
		return XDP_ABORTED;
	}

	// Since nh_off is used as offset into the packet the verifier doesn't
	// allow us to use meta->nh_off directly even if we check that 'data + meta->nh_off <= data' is true.
	// Because this switch will cause nh_offset to be 0 or one of the cases the verifier can check every
	// permutation to see that it is correct. (using inline assebly we can most likely add checks to meta->nh_off
	// which will then allow it to use a dynamic value between data and data_end but I have not yet figured
	// out how to do it via C.)
	__u32 nh_off;
	switch (meta->nh_off) {
		case sizeof(struct ethhdr):
			nh_off = sizeof(struct ethhdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
		break;
	}

	struct iphdr* iph = data + nh_off;
	nh_off += sizeof(struct iphdr);
	__u64 framesize = data_end - data;

	// Drop packets which don't have enough data to fit the IPv4 header
	if( data + nh_off > data_end ){
		return XDP_DROP;
	}

	__u8 ipproto = iph->protocol;

    inc_ip_proto(ipproto, framesize);

	meta->nh_off = nh_off;

	if( ipproto == IPPROTO_UDP ){
        bpf_tail_call(ctx, &tails, PARSE_UDP);

		return XDP_ABORTED;
    }

    if( ipproto == IPPROTO_TCP ){
        bpf_tail_call(ctx, &tails, PARSE_TCP);
		
		return XDP_ABORTED;
    }

	return XDP_PASS;
}

SEC("xdp")
int ipv6_prog(struct xdp_md* ctx) {
	void *data      = (void *)(unsigned long)ctx->data;
	void *data_end  = (void *)(unsigned long)ctx->data_end;
	
	/* Check data_meta have room for meta_info struct */
	struct meta_info* meta = (void *)(unsigned long)ctx->data_meta;
	if( meta + 1 > data ){
		return XDP_ABORTED;
	}

	// Since nh_off is used as offset into the packet the verifier doesn't
	// allow us to use meta->nh_off directly even if we check that 'data + meta->nh_off <= data' is true.
	// Because this switch will cause nh_offset to be 0 or one of the cases the verifier can check every
	// permutation to see that it is correct. (using inline assebly we can most likely add checks to meta->nh_off
	// which will then allow it to use a dynamic value between data and data_end but I have not yet figured
	// out how to do it via C.)
	__u32 nh_off;
	switch (meta->nh_off) {
		case sizeof(struct ethhdr):
			nh_off = sizeof(struct ethhdr);
		break;
		case sizeof(struct ethhdr) + sizeof(struct vlan_hdr):
			nh_off = sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
		break;
	}

	struct ipv6hdr* ip6h = data + nh_off;
	nh_off += sizeof(struct ipv6hdr);
	
	// Drop packets which don't have enough data to fit the IPv6 header
	if( data + nh_off > data_end ){
		return XDP_DROP;
	}

	__u8 ipproto = ip6h->nexthdr;
	__u64 framesize = data_end - data;

	inc_ip_proto(ipproto, framesize);

	meta->nh_off = nh_off;

    if( ipproto == IPPROTO_UDP ){
        bpf_tail_call(ctx, &tails, PARSE_UDP);

		return XDP_ABORTED;
    }

    if( ipproto == IPPROTO_TCP ){
        bpf_tail_call(ctx, &tails, PARSE_TCP);
		
		return XDP_ABORTED;
    }

	return XDP_PASS;
}

SEC("xdp")
int entry_prog(struct xdp_md* ctx)
{
	/* Reserve space in-front of data pointer for our meta info.
	 * (Notice drivers not supporting data_meta will fail here!)
	 */
	int ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_info));
	if( ret < 0 ){
		return XDP_ABORTED;
	}

	/* Notice: Kernel-side verifier requires that loading of
	 * ctx->data and ctx->data_end MUST happen _after_ helper bpf_xdp_adjust_meta(),
	 * as pkt-data pointers are invalidated.  Helpers that require
	 * this are determined/marked by bpf_helper_changes_pkt_data()
	 */
	void* data		= (void *)(unsigned long)ctx->data;
	void* data_end 	= (void *)(long)ctx->data_end;

	/* Check data_meta have room for meta_info struct */
	struct meta_info* meta = (void *)(unsigned long)ctx->data_meta;
	if( meta + 1 > data ){
		return XDP_ABORTED;
	}

	// Since every program will parse its own part of the header, we somehow need to comunicate the next header offset
	// between programs. Since the only info passed to the next program is 'ctx' we need to store it in there.
	// This is where the metadata room we just allocated comes in.
	meta->nh_off = sizeof(struct ethhdr);

	// If we don't even have enough data to a ethernet frame header, drop the message
	if( data + meta->nh_off > data_end ){
		return XDP_DROP;
	}

	struct ethhdr* eth = data;
	__be16 h_proto = eth->h_proto;

	// If the ethernet packet contains a IEEE 802.1Q or 802.1AD VLAN header
	if( h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD) ){
		struct vlan_hdr* vhdr = data + meta->nh_off;
		meta->nh_off += sizeof(struct vlan_hdr);
		
		// Drop packets which don't have enough data to fit the VLAN header
		if( data + meta->nh_off > data_end ){
			return XDP_DROP;
		}

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if( h_proto == bpf_htons(ETH_P_IP) ){
		bpf_tail_call(ctx, &tails, PARSE_IPv4);
	} else if( h_proto == bpf_htons(ETH_P_IPV6) ){
		bpf_tail_call(ctx, &tails, PARSE_IPv6);
	}
	
	// If the program continues after the bpf_tail_call, an error was encounterd and the tail call was not executed
	// So abort.
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";