#!/bin/bash

# xdp_stats_test
clang -S -target bpf -Wall -O2 -emit-llvm -c -g -I/usr/include -o - xdp_stats_test.c | \
    llc -march=bpf -filetype=obj -o xdp_stats_test -