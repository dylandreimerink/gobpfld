#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/filter.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

SEC("sockfilter")
int sockfilter_prog(struct __sk_buff *skb)
{
    // Use SKF_NET_OFF to access the IP header which is needed since the skb only contains
    // the L4 (UDP) header since the associated socket is a UDP socket
    __be32 dst_addr = load_word(skb, SKF_NET_OFF + offsetof(struct iphdr, daddr));

    // drop traffic unless it is to 127.0.0.1
    const __be32 localhost = 0x7F000001;
    if( dst_addr != localhost ) {
        return 0;
    }

    int udp_len = load_half(skb, offsetof(struct udphdr, len));
    // bpf_printk("size: %d", sizeof(struct udphdr) + udp_len);
    return sizeof(struct udphdr) + udp_len;
}

char _license[] SEC("license") = "GPL";