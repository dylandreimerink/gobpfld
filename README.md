# GoBPFLD

GoBPFLD is a pure go eBPF loader/userspace library as an alternative to using [gobpf](https://github.com/iovisor/gobpf) which requires CGO to work. The goal of GoBPFLD is to provide a library for eBPF development which is comparable to libbpf(C library) but without CGO which improves the development experience.

> **WARNING** GoBPFLD is currently not (yet) feature complete, and may lack critical features for some eBPF program types since the main focus for now is on XDP programs.

> **WARNING** GoBPFLD has only been tested on X86_64 machines, due to the nature of interacting with the kernel via syscalls it is likely that architecture dependant bugs may arise. For now it is not recommended to trust this library with any architecture other than X86_64.

## Requirements

eBPF is a Linux specific feature (ignoring [userspace eBPF](https://github.com/generic-ebpf/generic-ebpf)) which was introduced in kernel 3.18. This means that for this library to work the executable must be run on a Linux machine with 3.18 or above.

This library detects (at runtime) which version of the linux kernel is being used. Higher level features will attempt to fallback to still over as much functionality as possible. This library attempts to catch the usage of unsupported features and return nice verbose human readable errors. If this fails the kernel will still return an error, which is less verbose. For some features running on a newer kernel version may be required. You can find a great overview of features per kernel version [here](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md).

## Security

Programs which interact with the kernel via the [bpf syscall](https://man7.org/linux/man-pages/man2/bpf.2.html) need to have extra [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) if they are not running as the root user. In particular the `CAP_BPF` or `CAP_SYS_ADMIN` capability. `CAP_BPF` is available since kernel 5.8 and is preferred since it has the least privileges needed. If you run on a kernel version lower than 5.8, `CAP_SYS_ADMIN` is the only option you have to grant non-root users access to the `bpf` syscall. In this case it might be a better option to run you program as root and switch to a non-root user when not using the bpf syscall. This can be accomplished by using the [seteuid](https://man7.org/linux/man-pages/man3/seteuid.3p.html) syscall via the [syscall.Seteuid](https://golang.org/pkg/syscall/#Setuid) function.

There are a number of eBPF related vulnerabilities known so far: [CVE-2016-2383](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2383), [CVE-2016-4557](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4557), [CVE-2021-20268](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20268). The kernel has the ability to JIT eBPF programs which translates the eBPF instruction into actual machine code to be executed. Not only that but it executes in the kernel with all associated privileges. To ensure that eBPF programs don't access memory outside the eBPF vm, the kernel attempts to detect illegal code, if the verifier fails we have security issues. Programs using this library therefor must be sure that the eBPF programs don't contain user input without sanitization. Even normal features of eBPF such as packet manipulation or dropping may be considered security issues in some cases. More info about eBPF JIT and eBPF hardening can be found in the [cilium reference guide](https://docs.cilium.io/en/latest/bpf/#jit)

## Use cases

GoBPFLD is a loader/library to make eBPF tool development in Go smoother. It is not a standalone tool like [bpftool](https://manpages.ubuntu.com/manpages/focal/man8/bpftool-prog.8.html) but rather more like libbpf or gobpf.

## Features

* Load pre-compiled eBPF programs from ELF files (see LoadProgramFromELF)
* Decode eBPF bytecode (see BPFProgram.DecodeToReader and ebpf.Decode)
* Encode eBPF instructions into bytecode (see ebpf.Encode)
* Loading eBPF maps into the kernel (see BPFMap.Load)
* Loading eBPF programs into the kernel (see BPFProgram.Load)
* Interacting with eBPF maps (get and set, more to follow)
* Attaching eBPF program to network interface as XDP program(see BPFProgram.XDPLinkAttach)
* Go wrappers around all bpf syscall commands (see bpfsys package)

## Examples

The cmd/examples directory contains examples programs which demonstrate how to use this library and its capabilities.

## eBPF useful links

* [Cilium BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
* [IOVisor eBPF features per kernel version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
* [XDP tutorial and simple examples](https://github.com/xdp-project/xdp-tutorial)
* [BPF helper functions manual page](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
* [Linux kernel (e)BPF socket filter document](https://github.com/torvalds/linux/blob/master/Documentation/networking/filter.rst)
* [Linux kernel (e)BPF documentation](https://github.com/torvalds/linux/tree/master/Documentation/bpf)
* [Linux kernel example programs](https://github.com/torvalds/linux/tree/master/samples/bpf)

## TODO/Roadmap/Scope limits

As mentioned earlier the first milestone/focus area of this project has been on implementing basic eBPF and XDP related features, and thus is missing a lot of stuff. This is a list of features to be added later, just to keep track.

### Must have

Features/tasks in this list are commonly used/requested because they are used in common use cases / scenarios.

* Data relocation from ELF files(static global variables)
* Attach to sockets
* Attach to kprobes
* Attach to tc (traffic control)
* Attach to tracepoints
* Attack to perf events
* Tailcall support
* ~~Map pinning and unpinning~~
* ~~Bulk map ops~~
* Program pinning and unpinning
* ~~BPF2BPF function calls~~
* Map iterator construct (looping over maps is very common)
* (partially implemented) Linux kernel version detection (so programs can programmatically decide which features they can use, then error, warn or be backwards compatible)

### Should have

Features/tasks in this list are not critical for most users but still important for a significant portion.

* Map in map support (useful but not widely used)
* XSK/AF_XDP support (useful for kernel bypass and packet capture)
* Program testing (Being able to unit test an XDP program would be great)
* Support for LWT programs (Light weight tunnel)
* BTF support (So we have more type info to work with)
* ARM64 support / testing (ARM is on the rise)
* ARM32 support / testing (ARM is on the rise)

### Could have

Features/tasks in this list are cool to have but secondary to the primary goal of this project.

* RISC-V support / testing (RISC-V has promise, would be cool, but not yet widely used)
* x86_32 support / testing (32 bit is not very popular anymore, but maybe still useful for IOT or raspberry pi like machines)
* Userspace VM (It would be cool to be able to run eBPF in Go, for testing or as plugin mechanism like LUA and WASM. But not an important feature related to eBPF loading)
* Userspace map caching (Depending on the map flags and eBPF program, maps can be cached in the userspace without requesting value via syscalls (userspace -> kernel only maps))

### Won't have

Features/tasks in this list are out of the scope of the project. We have to draw the line somewhere to avoid feature creep.

* cBPF support (cBPF is not even supported by Linux anymore, just converted to eBPF, which you can also do with [tools](https://github.com/cloudflare/cbpfc) for any exiting program)

## eBPF troubleshooting and known issues

eBPF can be very difficult at times, I have identified two reasons so far. The first being that errors returned by syscalls can mean any of a thousands things in a general category, like a hint, the rest is trail and error. The second is that the verifier is very strict.

### Common verifier errors

#### EPERM(1) - Operation not permitted

* Program is executed as non-root user without CAP_BPF or CAP_SYS_ADMIN

#### E2BIG(7) - Arg list too long

* Program has to many instruction (older kernels only allow 4096 instructions per program, newer kernels >100000)

#### ENOMEM(12) - Out of memory

* A userspace buffer sent to the kernel is to small(verifier log(1 MiB default) is suspect for large programs)
* System is out of RAM and can't allocate memory for the eBPF VM/verifier/ect.

#### EACCES(13) - Permission denied

* Verifier error (check verifier log for details)

#### EFAULT(14) - Bad address

* Bug in gobpfld code (invalid pointers sent to the syscall)

#### EINVAL(22) - Invalid argument

* Verifier error (check verifier log for details)
* Bug in gobpfld code (invalid argument sent to the syscall)
