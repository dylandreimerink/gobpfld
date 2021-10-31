#!/bin/bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h && \
    clang -D__TARGET_ARCH_x86 -S -target bpf -Wall -O2 -emit-llvm -c -g -I/usr/include -o - bash_stats.c | \
    llc -march=bpf -filetype=obj -o bash_stats -