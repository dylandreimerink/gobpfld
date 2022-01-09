# GoBPFLD

[![GoDoc](https://pkg.go.dev/badge/github.com/dylandreimerink/gobpfld)](https://pkg.go.dev/github.com/dylandreimerink/gobpfld)

GoBPFLD is a pure go eBPF loader/userspace library as an alternative to using [gobpf](https://github.com/iovisor/gobpf) which requires CGO to work. The goal of GoBPFLD is to provide a library for eBPF development which is comparable to libbpf(C library) but without CGO which improves the development experience.

> **WARNING** GoBPFLD is currently not (yet) feature complete, and may lack critical features for some eBPF program types. This library is still fairly young and the API is still subject to change.

> **WARNING** GoBPFLD has only been tested on X86_64 machines, due to the nature of interacting with the kernel via syscalls it is likely that architecture dependant bugs may arise. For now it is not recommended to trust this library with any architecture other than X86_64.

## Requirements

eBPF is a Linux specific feature (ignoring [userspace eBPF](https://github.com/generic-ebpf/generic-ebpf)) which was introduced in kernel 3.18. This means that for this library to work the executable must be run on a Linux machine with 3.18 or above.

This library detects (at runtime) which version of the linux kernel is being used. Higher level features will attempt to fallback to still offer as much functionality as possible. This library attempts to catch the usage of unsupported features and return nice verbose human readable errors. If this fails the kernel will still return an error, which is less verbose. For some features running on a newer kernel version may be required. You can find a great overview of features per kernel version [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md).

## Security

Programs which interact with the kernel via the [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html) need to have extra [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) if they are not running as the root user. In particular the `CAP_BPF` or `CAP_SYS_ADMIN` capability. `CAP_BPF` is available since kernel 5.8 and is preferred since it has the least privileges needed. If you run on a kernel version lower than 5.8, `CAP_SYS_ADMIN` is the only option you have to grant non-root users access to the `bpf` syscall. In this case it might be a better option to run you program as root and switch to a non-root user when not using the bpf syscall. This can be accomplished by using the [seteuid](https://man7.org/linux/man-pages/man3/seteuid.3p.html) syscall via the [syscall.Seteuid](https://golang.org/pkg/syscall/#Setuid) function.

Programs that use tracepoints, kprobes, and/or uprobes also require the `CAP_SYS_ADMIN` capability in kernels versions below 5.8. Since kernel 5.8 the `CAP_PERFMON` capability can be assigned which specifically grants the permissions required and no more.

There are a number of eBPF related vulnerabilities known so far: [CVE-2016-2383](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2383), [CVE-2016-4557](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4557), [CVE-2021-20268](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20268). The kernel has the ability to JIT eBPF programs which translates the eBPF instruction into actual machine code to be executed. Not only that but it executes in the kernel with all associated privileges. To ensure that eBPF programs don't access memory outside the eBPF vm, the kernel attempts to detect illegal code, if the verifier fails we have security issues. Programs using this library therefor must be sure that the eBPF programs don't contain user input without sanitization. Even normal features of eBPF such as packet manipulation or dropping may be considered security issues in some cases. More info about eBPF JIT and eBPF hardening can be found in the [cilium reference guide](https://docs.cilium.io/en/latest/bpf/#jit)

## Features

* Pure Go - no CGO, missing libraries, forced dynamic linking, ect.
* Load pre-compiled eBPF programs from ELF files
* eBPF bytecode decoder 
* eBPF instructions to bytecode encoder
* eBPF clang style assembly parser/assembler
* Loading eBPF maps into the kernel 
* Loading eBPF programs into the kernel
* Interacting with eBPF maps (lookup, set, delete, batch-lookup, batch-set, and batch-delete)
* Map iterators
* Attaching eBPF programs to network interfaces as XDP programs
* Attaching eBPF programs to sockets
* Attaching eBPF programs to tracepoints, kprobes, and uprobes
* XSK/AF_XDP socket support
* Go wrappers around all bpf syscall commands
* XDP program testing
* Array map memory mapping
* BTF loading

## Motivation

GoBPFLD is a loader/library to make eBPF tool development in Go smoother. It is not a standalone tool like [bpftool](https://manpages.ubuntu.com/manpages/focal/man8/bpftool-prog.8.html) but rather more like libbpf or gobpf.

The kernel developers also maintain [libbpf](https://github.com/libbpf/libbpf) which is the most up-to-date library for eBPF program loading. This is great for C or C++ developers, but we userspace programmers would like to also use different programming languages. The most common solution is to create a wrapper library around the C API. In the case of go we would use CGO for this, the downside of CGO is that it has negative effects on features of Go like static linking, dependency management, and cross-compiling. GoBPFLD is written in pure Go so we still retain all the benefits and feature we love in Go.

Once catch is that there currently is no way(that I know of) to generate eBPF programs from higher level programing languages other than C. Altho technically possible since LLVM is used in clang to compile the programs, it has not yet been done. This means that you will still need to compile any eBPF programs with a clang pipeline if you are not willing to create eBPF programs in eBPF-assembly. But since the eBPF programs are a separate code base the generated ELF files can just be embedded in your Go application or shipped and loaded from file without compromise.

In a number of use cases you might want to generate an eBPF program completely dynamically, a classic example of this is `tcpdump`. In this case no C code is required at all. As far as I know there are no libraries with specific support for this, and creating the required eBPF bytecode yourself is quite hard.
The `ebpf` sub-package attempts to improve the process of crafting your own dynamic programs by providing an abstraction between the instructions and byte representation. The package allows you to decompile a program into its instructions, every instruction has a Go type so properties can be changed without worrying about the binary representation. These instruction types can be used to craft a program fully from Go and to recompile them into a program which can be loaded. The package also provides a assembler which is compatible with the text assembly used by clang, thus allowing you to write your program as an assembly string and turn that into a program. Using the text based assembler can be easier since it allows you to use labels without manually tracking offsets in the instructions. So developers will require some knowledge about the eBPF instruction set, but should be able to focus more on the the functionality of their own application.

## Examples

The cmd/examples directory contains examples programs which demonstrate how to use this library, its capabilities, and the capabilities of eBPF.

## eBPF useful links

* [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
* [IOVisor eBPF features per kernel version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
* [XDP tutorial and simple examples](https://github.com/xdp-project/xdp-tutorial)
* [BPF helper functions manual page](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
* [Linux kernel (e)BPF socket filter document](https://github.com/torvalds/linux/blob/master/Documentation/networking/filter.rst)
* [Linux kernel (e)BPF documentation](https://github.com/torvalds/linux/tree/master/Documentation/bpf)
* [Linux kernel example programs](https://github.com/torvalds/linux/tree/master/samples/bpf)

## TODO/Roadmap/Scope limits

As mentioned earlier the first milestone/focus area of this project has been on implementing basic eBPF and XDP related features, and thus is missing a lot of stuff. At some point the API of this library should become backwards compatible along the lines of the [go 1 compatibility promise](https://golang.org/doc/go1compat), though I don't yet know when this will be.

This is a list of features to be added later, just to keep track.

### Must have

Features/tasks in this list are commonly used/requested because they are used in common use cases / scenarios.

* ~~Data relocation from ELF files(static global variables)~~
* ~~Attach to sockets~~
* ~~Attach to kprobes~~
* ~~Attach to kretprobes~~
* ~~Attach to uprobes~~
* ~~Attach to tracepoints~~
* ~~Tailcall support~~
* ~~Map pinning and unpinning~~
* ~~Bulk map ops~~
* ~~Program pinning and unpinning~~
* ~~BPF2BPF function calls~~
* ~~Map iterator construct (looping over maps is very common)~~
* Support perf event array maps
* Support stack trace maps
* Support dev and devhash map
* Support sock and sockhash map
* Support cpu map
* Support queue map
* ~~Support stack map~~
* Support ringbuffer map
* Attach to tc (traffic control)
* ~~Linux kernel version detection (so programs can programmatically decide which features they can use, then error, warn or be backwards compatible)~~
* Library testing framework (We need some way to guarantee the library works, and stays working)
  * ~~Library+kernel testing, verify the ABI is implemented correctly~~
  * Fuzzing, we parse a lot like ELF files, eBPF programs, assembly. Panics are not desirable.
  * Race condition testing
  * Cross architecture testing, [QEMU](https://www.qemu.org/) supports [emulation](https://www.qemu.org/docs/master/system/index.html) of other architectures which we should be able to use to test architectures like ARM and RISC-V without dedicated testing hardware.
  * ~~Cross kernel version testing, we should run the tests on a number of kernels, both older and newer, to test version dependant fallbacks and kernel ABI issues.~~

### Should have

Features/tasks in this list are not critical for most users but still important for a significant portion.

* ~~XSK/AF_XDP support (useful for kernel bypass and packet capture)~~
* ~~Map access via memory mapping https://lwn.net/Articles/805043/ (could improve performance)~~
* ~~Map in map support (useful but not widely used)~~
* XSK multiple sockets per netdev,queue pair (currently only one socket per pair is supported)
* (partially implemented) Program testing (Being able to unit test an XDP program would be great)
* Support reuse port sock array map
* Support cGroup storage maps
* Support SK storage map
* Support struct ops map
* Support inode storage map
* Support task storage map
* Support for LWT programs (Light weight tunnel)
* ~~BTF support (So we have more type info to work with, some newer features require BTF support in the loader)~~
* ARM64 support / testing (ARM is on the rise)
* ARM32 support / testing (ARM is on the rise)
* ELF symbols to offset functionality for perf package

### Could have

Features/tasks in this list are cool to have but secondary to the primary goal of this project.

* Built-in XSK kernel program (like libbpf) (only useful for people intrested in full kernel bypass without additional logic in XDP/eBPF)
* RISC-V support / testing (RISC-V has promise, would be cool, but not yet widely used)
* x86_32 support / testing (32 bit is not very popular anymore, but maybe still useful for IOT or raspberry pi like machines)
* Userspace VM (It would be cool to be able to run eBPF in Go, for testing or as plugin mechanism like LUA and WASM. But not an important feature related to eBPF loading)
* Userspace map caching (Depending on the map flags and eBPF program, maps can be cached in the userspace without requesting value via syscalls (userspace -> kernel only maps))

### Won't have

Features/tasks in this list are out of the scope of the project. We have to draw the line somewhere to avoid feature creep.

* cBPF support (cBPF is not even supported by Linux anymore, just converted to eBPF, which you can also do with [tools](https://github.com/cloudflare/cbpfc) for any exiting program)
