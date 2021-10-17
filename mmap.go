package gobpfld

import _ "unsafe" // Need to import unsafe to allow the go:linkname directive

// mmap is a link to the unexposed syscall.mmap which allows us to call the mmap function without restrictions.
// This is nessessery to allow us to specify our own addr, which we can't via the exported syscall.Mmap function.
//go:linkname mmap syscall.mmap
func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error)
