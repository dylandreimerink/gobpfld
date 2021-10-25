#!/bin/bash
clang -S -target bpf -Wall -O2 -emit-llvm -c -g -I/usr/include -o - basic03_map_counter.c | \
    llc -march=bpf -filetype=obj -o basic03_map_counter -