package syscall

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// ENOTSUPP - Operation is not supported
const ENOTSUPP = unix.Errno(524)

// a map of string translations for syscall errors which are no included in the standard library
var nonStdErrors = map[unix.Errno]string{
	ENOTSUPP: "Operation is not supported",
}

// Error is an error wrapper for syscall errors
type Error struct {
	// Context specific error information since the same code can have different
	// meaning depending on context
	Err string
	// The underlaying syscall error number
	Errno unix.Errno
}

func (e *Error) Error() string {
	errStr := nonStdErrors[e.Errno]
	if errStr == "" {
		errStr = e.Errno.Error()
	}

	if e.Err == "" {
		return fmt.Sprintf("%s (%d)", errStr, e.Errno)
	}

	return fmt.Sprintf("%s (%s)(%d)", e.Err, errStr, e.Errno)
}
