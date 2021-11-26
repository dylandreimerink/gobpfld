package syscall

import "golang.org/x/sys/unix"

func IOCtl(fd int, req uint, arg uintptr) (err error) {
	_, _, e1 := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), arg)
	if e1 != 0 {
		err = &Error{
			Errno: e1,
		}
	}
	return
}
