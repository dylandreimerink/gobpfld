

/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>

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


// Stats on packets keyed by protocol number
struct bpf_map_def SEC("maps") cnt_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 8,
};

SEC("xdp")
int percpumap_prog(struct xdp_md *ctx)
{
    __u32* key = 0;
	__u64* val = bpf_map_lookup_elem(&cnt_map, &key);
    if( val != NULL ){
        (*val)++;
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";