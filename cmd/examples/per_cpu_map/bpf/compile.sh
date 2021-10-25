#!/bin/bash
clang -S -target bpf -Wall -O2 -emit-llvm -c -g -I/usr/include -o - percpu.c | \
    llc -march=bpf -filetype=obj -o percpu -