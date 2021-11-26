package syscall

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type Socklen uint32

// Bind is a public version of the unix.bind without additional wrappers which allows us to use any
// value type we want. But does require the usage of unsafe.
func Bind(s int, addr unsafe.Pointer, addrlen Socklen) (err error) {
	_, _, e1 := unix.Syscall(unix.SYS_BIND, uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = &Error{
			Errno: e1,
		}
	}
	return
}
