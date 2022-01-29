package emulator

// These error codes are defined by linux and used to return errors from eBPF helper calls
// https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/errno-base.h

// Argument list too long
func e2big() *IMMValue {
	return newIMM(-7)
}

// Bad address
func efault() *IMMValue {
	return newIMM(-14)
}
