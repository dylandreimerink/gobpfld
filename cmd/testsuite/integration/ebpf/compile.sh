#!/bin/bash

# xdp_stats_test
clang -target bpf -Wall -O2 -g -c xdp_stats_test.c -I/usr/include -o xdp_stats_test
# global_data_test
clang -target bpf -Wall -O2 -g -c global_data_test.c -I/usr/include -o global_data_test