#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

/* llvm builtin functions that eBPF C program may use to
 * emit BPF_LD_ABS and BPF_LD_IND instructions
 */
unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");

SEC("sockfilter")
int sockfilter_prog(struct __sk_buff *skb)
{
    __be16 h_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    if( h_proto != ETH_P_IP ) {
        return 0;
    }

    int ip_proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
    if( ip_proto != IPPROTO_ICMP ) {
        return 0; 
    }

   return skb->len;
}

char _license[] SEC("license") = "GPL";