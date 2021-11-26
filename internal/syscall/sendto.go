package syscall

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Zero single-word zero for use when we need a valid pointer to 0 bytes.
// See mkunix.pl.
var Zero uintptr

// Sendto is a public version of the unix.sendto without additional wrappers which allows us to use any
// value type we want. But does require the usage of unsafe.
func Sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen Socklen) (err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&Zero)
	}
	_, _, e1 := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(s),
		uintptr(_p0),
		uintptr(len(buf)),
		uintptr(flags),
		uintptr(to),
		uintptr(addrlen),
	)
	if e1 != 0 {
		err = &Error{
			Errno: e1,
		}
	}
	return
}
