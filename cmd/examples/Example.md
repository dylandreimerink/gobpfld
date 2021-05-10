# Examples

This directory contains a number of small example programs which demonstrate aspects of the library.

## xdp_stats

This program demonstrates the loading of a simple XDP eBPF program. The program is in ELF format and made using the C Clang+llvm toolchain. It is the Basic03 example from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter) but the userspace side of the example is replaced by this go program.

It demonstrates opening and decoding an ELF file into a BPFProgram and BPFMap, loading the program and map into the kernel, attaching the program to the loopback interface and reading the stats reported by the XDP program from the map.

## xdp_stats_assembly

This program is functionally identical to the xdp_stats example, but the program is not loaded from an ELF file, rather the `ebpf` package is used to craft the same program from individual instructions.

It demonstrates how userspace applications can generate programs dynamically without needing a full toolchain to build the programs.

## per_cpu_map

This eBPF program attaches to the loopback interface of the host and counts the amount of packets received per CPU, it stores this information in a `BPF_MAP_TYPE_PERCPU_ARRAY` map. This example demonstrates how to read from and write to a per CPU map type with the `gopbfld.BPFGenericMap`.

## map_batch

This example demonstrates batch operations on maps. Batch operations offer speed improvements over non-batch operations since less syscalls/context switches are required for the same amount of work.

## map_iterator

This example demonstrates the usage of map iterators to loop over maps. Iterators provide an easier API than using syscalls directly to loop over maps.

## map_pinning

This program demonstrates how to pin and unpin maps to the bpf FS using gobpfld.

## bpf_to_bpf

This eBPF program demonstrates [BPF to BPF calls](https://docs.cilium.io/en/stable/bpf/#bpf-to-bpf-calls). It shows that gobpfld can relocate code from the `.text` section of ELF files and recalculate the addresses of call instructions.

The program records traffic usage per IP protocol, UDP destination port and TCP destination port. Since the program support both IPv4 and IPv6 it is a good demo of BPF to BPF since without this feature the `inc_*` functions whould have to be inlined multiple times.

The `handle_ipv4` and `handle_ipv6` functions in turn call the `inc_ip_proto`, `inc_udp`, and `inc_tcp` functions thus showing that multiple calls are possible. The `inc_*` functions access maps which verifies that map FD relocations in the `.text` ELF section are also handled.

During loading the verbose verifier log is dumped which confirms the usage of BPF to BPF calls in the first few lines: 
```
BPF Verifier log:
func#0 @0
func#1 @27
func#2 @59
func#3 @91
func#4 @118
func#5 @147
```

## icmp_pcap

This examples creates a raw socket and uses a eBPF program to filter out just ICMP traffic. It demonstrates how to write a socket filter program as well as how to attach a eBPF program to a socket using a file descriptor.

## udp_socket_filter

This examples creates an udp socket which listens on *:3000 using the stdlib net package. The eBPF program is then attached via the net.ListenConfig.Control callback. Event tho the socket listens on all ip addresses the eBPF program filters all traffic accept those with destination address 127.0.0.1.

## xsk_echo_reply

This examples shows how to implement a ICMP echo reply (ping response) using XSK/[AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html). XSK(XDP socket) allows us to perform kernel bypass using XDP. We do this by creating a network socket, much like a normal network socket. Instead of binding it to an port and/or IP we just bind it to a network interface and NIC Queue. A XDP program is attached to the same network interface, this program now has the ability to send frames over this socket directly to the userspace application, thus bypassing the kernel network stack.

We can also transmit to this socket which again bypasses the kernel stack. The technique is quite advanced and requires a lot of work in userspace to use (userspace network stack/packet decoding). However it is also very powerful, applications vary from virtualization to super fast packet capture. A major advantage of XSK is that we can directly read from and write to the same memory buffer the network driver will use to transmit and recieve data. This offers great performance because no memory has to change context (userspace<->kernel).

The example implements manual packet decoding, this is done so this example doesn't cause the whole library to have extra dependencies. But a packet decoding/encoding library like [gopacket](https://github.com/google/gopacket) comes highly recommended.

## TODO

* xsk encapsulation example
* xsk write lease example
* xsk multi queue example (single rountine and multi routine)
