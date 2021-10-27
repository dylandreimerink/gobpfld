#include "vmlinux.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") execve_stats = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif


/* kprobe is NOT a stable ABI
 * kernel functions can be removed, renamed or completely change semantics.
 * Number of arguments and their positions can change, etc.
 * In such case this bpf+kprobe example will no longer be meaningful
 */
SEC("kprobe/__x64_sys_execve")
int bpf_prog1(struct pt_regs *ctx)
{
	__u64 *counter;
	__u32 key = 0;
	counter = bpf_map_lookup_elem(&execve_stats, &key);
	if (!counter)
		return 0;

	lock_xadd(counter, 1);

	return 0;
}

char _license[] SEC("license") = "GPL";