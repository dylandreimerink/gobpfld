package syscall

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Getsockopt is a public version of the unix.getsockopt without additional wrappers which allows us to use any
// value type we want. But does require the usage of unsafe.
func Getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *Socklen) (err error) {
	_, _, e1 := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		uintptr(unsafe.Pointer(vallen)),
		0,
	)
	if e1 != 0 {
		err = &Error{
			Errno: e1,
		}
	}
	return
}

// Setsockopt is a public version of the unix.setsockopt without additional wrappers which allows us to use any
// value type we want. But does require the usage of unsafe.
func Setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(s),
		uintptr(level),
		uintptr(name),
		uintptr(val),
		vallen,
		0,
	)
	if e1 != 0 {
		err = &Error{
			Errno: e1,
		}
	}
	return
}
