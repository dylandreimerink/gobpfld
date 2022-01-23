// package emulator contains a userspace emulator/runtime for eBPF.
//
// The primary use cases I can currently think of are:
// * Debugging, we can't debug eBPF programs when they run in the kernel, it would be nice if we have the option
//   to start a debugger session for an eBPF program just like we do with dlv or gdb for userspace applications.
// * Dynamic program extension, ultimately eBPF was made as a sort of plugin language for the kernel, but it doesn't
//   have to be limited to that. We could create a plugin system for go programs based on eBPF code, much like how
//   some people use lua or javascript.
//
// eBPF was originally developed for use in Linux, but it doesn't have to be limited to that. In fact work is already
// underway to use eBPF in BSD's and Windows. There is noting inherently "Linux" about eBPF itself, all of the "Host"
// specific features are implemented via map types and helper functions. Therefor this emulator is architected in such
// a way that it can be used for both Linux-flavored eBPF programs as well as others inclusing custom map and helper
// function types dedicated for other applications.
package emulator
