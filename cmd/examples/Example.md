# Examples

This directory contains a number of small example programs which demonstrate aspects of the library.

## xdp_stats

This program demonstrates the loading of a simple XDP eBPF program. The program is in ELF format and made using the C Clang+llvm toolchain. It is the Basic03 example from [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter) but the userspace side of the example is replaced by this go program.

It demonstrates opening and decoding an ELF file into a BPFProgram and BPFMap, loading the program and map into the kernel, attaching the program to the loopback interface and reading the stats reported by the XDP program from the map.

## xdp_stats_instructions

This program is functionally identical to the xdp_stats example, but the program is not loaded from an ELF file, rather the `ebpf` package is used to craft the same program from individual instructions.

It demonstrates how userspace applications can generate programs dynamically without needing a full toolchain to build the programs.

## xdp_stats_assembly

This program is almost identical to the `xdp_stats_instructions` example, except it replaces the manual instruction crafting with eBPF assembly code which is parsed and turned into eBPF instruction by the `ebpf` package.

## kprobe_execve_stats

This program attaches to the `execve` syscall which is called any time a program is executed on linux. The program simply counts the occurrences, more advanced programs can inspect the passed arguments.

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

## tailcall

This eBPF program demonstrates [Tail calls](https://docs.cilium.io/en/stable/bpf/#tail-calls). It is functionally identiacal to the BPF to BPF example except the functions for the different protocols are implemented as separate programs linked together using tail calls.

When tail calling another program the called program fully takes over and never returns back to the original program. This feature has a number of useful use cases, but does require some setup. For example tail calls allows multiple, seperatly compiled programs to cooperate. A security team can write a tool for network auditing and a networking team another program for forwarding, by sticking a small program enfront of both which can make the decition on which program should be called these two programs from different maintainers can run on the same network device. And since they are not the same program they can be seperatly upgraded and have separate userspace applications to manage both (assuming the userspace programs can coordinate the loading/unloading sequence).

Another usecase for a/b testing one or multiple variations of a eBPF program. Yet another is for using multiple generated XDP programs on the same network device. The posibilities are endless realy.

However one must also keep the folloing limitations in mind:
 * Tail calls have a limited depth(max 16 tail calls)
 * Tail calls have no arguments, any data must be passed via the program specific context or via per-cpu maps(because all tail calls will be executed on the same CPU without interruptions between them, per cpu maps can be safely used as scratch buffers)
 * Programs can only tail call to other programs of the same type and both must JIT'ed or both interperted, can't mix JIT and interperted eBPF programs.

## icmp_pcap

This example creates a raw socket and uses a eBPF program to filter out just ICMP traffic. It demonstrates how to write a socket filter program as well as how to attach a eBPF program to a socket using a file descriptor.

## udp_socket_filter

This example creates an udp socket which listens on *:3000 using the stdlib net package. The eBPF program is then attached via the net.ListenConfig.Control callback. Event tho the socket listens on all ip addresses the eBPF program filters all traffic accept those with destination address 127.0.0.1.

## test_xdp_program

This example example domonstrates how to test an XDP program without actually attaching the program to a link and sending actual traffic. Once a eBPF is loaded into the kernel we can ask the kernel to call the program X of times with data that is specified by us. The kernel will return the return value, the updated packet and the duration of execution in nanoseconds. 

This is useful in a number of cases, for example:
  * Programatically testing XDP programs like a unit or intergration test.
  * Testing a program on production traffic (by capturing/mirroring frames with a raw socket and passing to the XDP program) 
  * Emulating hard to create edge cases (corrupt packets/failed checksums)
  * Benchmarking XDP programs

## xsk_echo_reply

This example shows how to implement a ICMP echo reply (ping response) using XSK/[AF_XDP](https://www.kernel.org/doc/html/latest/networking/af_xdp.html). XSK(XDP socket) allows us to perform kernel bypass using XDP. We do this by creating a network socket, much like a normal network socket. Instead of binding it to an port and/or IP we just bind it to a network interface and NIC Queue. A XDP program is attached to the same network interface, this program now has the ability to send frames over this socket directly to the userspace application, thus bypassing the kernel network stack.

We can also transmit to this socket which again bypasses the kernel stack. The technique is quite advanced and requires a lot of work in userspace to use (userspace network stack/packet decoding). However it is also very powerful, applications vary from virtualization to super fast packet capture. A major advantage of XSK is that we can directly read from and write to the same memory buffer the network driver will use to transmit and recieve data. This offers great performance because no memory has to change context (userspace<->kernel).

The example implements manual packet decoding, this is done so this example doesn't cause the whole library to have extra dependencies. But a packet decoding/encoding library like [gopacket](https://github.com/google/gopacket) comes highly recommended.

## xsk_multi_sock

This example is a variation on the xsk_echo_reply example. The main difference is that this example works on multi queue NIC's. On systems with multi queue NIC's incomming traffic is distribured amoung all RX queues based on flow(different fields depending on the protocol stack). Using the [ethtool](https://linux.die.net/man/8/ethtool) utility this behavour can be changed.

So by default, in order to use XSK on a whole network device you need to bind a XSK to every RX/TX queue. Since a XSK can only be bound to 1 queue at a time it means you will have to manage a number of them. At first it might seem possible to redirect all frames to one socket since you can pick which socket to use in the XDP program. Unfortunately this doesn't work, XDP is only allowed to redirect to sockets bound on the same queue as where the frame enters. The XSK map is only meant for situations where there is more than one socket bound per queue(not yet supported by GoBPFLD).

To make interacting with multiple sockets easier GoBPFLD provides the `XSKMultiSocket` which can be created using the `NewXSKMultiSocket` function. This multi socket has same functions as the `XSKSocket` except it balances reads and writes between all sockets contained in it. Using the multi socket does mean that reading and writing to the socket is limited to one goroutine. The `XSKMultiSocket` like the `XSKSocket` is not concurrent, only one goroutine can read or write to it at a time. Thus if latency or throughput is important it is recommended to not use the `XSKMultiSocket` and instead start a separate goroutine for each `XSKSocket`. Do keep in mind that when not using the `XSKMultiSocket` you are responsible for balancing outgoing(TX) packages across the sockets.

The example contains both aproaches which can be selected using a flag.

## TODO

* xsk encapsulation example
* xsk write lease example
* LPM trie example
* Map op maps example
