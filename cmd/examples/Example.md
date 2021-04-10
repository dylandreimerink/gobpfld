# Examples

This directory contains a number of small example programs which demonstrate aspects of the library.

## xdp_stats

This program demonstrates the loading of a simple XDP eBPF program. The program is in ELF format and made using the C Clang+llvm toolchain. It is the Basic03 example from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter) but the userspace side of the example is replaced by this go program.

It demonstrates opening and decoding an ELF file into a BPFProgram and BPFMap, loading the program and map into the kernel, attaching the program to the loopback interface and reading the stats reported by the XDP program from the map.

## xdp_stats_assembly

This program is functionally identical to the xdp_stats example, but the program is not loaded from an ELF file, rather the `ebpf` package is used to craft the same program from individual instructions.

It demonstrates how userspace applications can generate programs dynamically without needing a full toolchain to build the programs.
