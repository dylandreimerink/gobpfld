#!/bin/bash
clang -S -target bpf -Wall -O2 -emit-llvm -c -g -I/usr/include -o - map_in_map_counter.c | \
    llc -march=bpf -filetype=obj -o map_in_map_counter -