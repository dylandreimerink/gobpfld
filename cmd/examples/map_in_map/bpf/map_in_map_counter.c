/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>

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

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct datarec {
	__u64 rx_packets;
};

struct bpf_map_def SEC("maps") map_of_maps = {
	.type        = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 2,
};


/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int  xdp_stats1_func(struct xdp_md *ctx)
{	
	__u32 key = 0;

	// Lookup the pointer to the map inner map
	struct bpf_map_def *stats_map = bpf_map_lookup_elem(&map_of_maps, &key);
	if (!stats_map) {
		return XDP_ABORTED;
	}

	// Lookup datarec struct in inner map, we will use key
	struct datarec *rec;
	key = XDP_PASS; /* XDP_PASS = 2 */

	rec = bpf_map_lookup_elem(stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
