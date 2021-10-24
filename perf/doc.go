// Package perf contains logic to interact with the linux perf subsystem. The open_perf_event syscall ABI and debugfs
// logic is large enough to warrant its own package so as to not clutter up the gobpfld package. The functionality in
// this package will be used to attach kprobe, tracepoint, perf event, raw tracepoint and trancing programs.
package perf
