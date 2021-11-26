package syscall

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type BPFAttribute interface {
	ToPtr() unsafe.Pointer
	Size() uintptr
}

// Bpf is a wrapper around the BPF syscall, so a very low level function.
func Bpf(cmd int, attr BPFAttribute, size int) (fd uintptr, err error) {
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr.ToPtr()), uintptr(size))
	if errno != 0 {
		err = &Error{
			Errno: errno,
		}
	}
	return
}
