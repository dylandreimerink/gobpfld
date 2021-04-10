// This file is only included on amd64

// +build amd64,linux

package bpfsys

// BPF syscall number https://github.com/torvalds/linux/blob/master/tools/lib/bpf/bpf.c#L39
const SYS_BPF = 321
