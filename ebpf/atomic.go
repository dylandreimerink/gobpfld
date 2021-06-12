package ebpf

import "fmt"

var _ Instruction = (*AtomicAdd)(nil)

type AtomicAdd struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (aa *AtomicAdd) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_ADD)
	if aa.Fetch {
		imm = int32(BPF_ADD | BPF_FETCH)
	}

	// TODO only 32bit and 64bit is supported

	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(aa.Size) | BPF_ATOMIC,
			Reg: NewReg(aa.Src, aa.Dest),
			Off: aa.Offset,
			Imm: imm,
		},
	}, nil
}

func (aa *AtomicAdd) String() string {
	sign := "+"
	offset := aa.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if aa.Size == BPF_W {
		reg = "w"
	}

	return fmt.Sprintf("lock *(%s *)(r%s %s %d) += %s%s", aa.Size, aa.Dest, sign, offset, reg, aa.Src)
}

var _ Instruction = (*AtomicSub)(nil)

type AtomicSub struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (as *AtomicSub) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_SUB)
	if as.Fetch {
		imm = int32(BPF_SUB | BPF_FETCH)
	}

	// TODO only 32bit and 64bit is supported

	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(as.Size) | BPF_ATOMIC,
			Reg: NewReg(as.Src, as.Dest),
			Off: as.Offset,
			Imm: imm,
		},
	}, nil
}

func (as *AtomicSub) String() string {
	sign := "+"
	offset := as.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if as.Size == BPF_W {
		reg = "w"
	}

	return fmt.Sprintf("lock *(%s *)(r%s %s %d) -= %s%s", as.Size, as.Dest, sign, offset, reg, as.Src)
}

var _ Instruction = (*AtomicAnd)(nil)

type AtomicAnd struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (aa *AtomicAnd) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_AND)
	if aa.Fetch {
		imm = int32(BPF_AND | BPF_FETCH)
	}
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(aa.Size) | BPF_ATOMIC,
			Reg: NewReg(aa.Src, aa.Dest),
			Off: aa.Offset,
			Imm: imm,
		},
	}, nil
}

func (aa *AtomicAnd) String() string {
	sign := "+"
	offset := aa.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if aa.Size == BPF_W {
		reg = "w"
	}

	return fmt.Sprintf("lock *(%s *)(r%s %s %d) &= %s%s", aa.Size, aa.Dest, sign, offset, reg, aa.Src)
}

var _ Instruction = (*AtomicOr)(nil)

type AtomicOr struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (ao *AtomicOr) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_OR)
	if ao.Fetch {
		imm = int32(BPF_OR | BPF_FETCH)
	}
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(ao.Size) | BPF_ATOMIC,
			Reg: NewReg(ao.Src, ao.Dest),
			Off: ao.Offset,
			Imm: imm,
		},
	}, nil
}

func (ao *AtomicOr) String() string {
	sign := "+"
	offset := ao.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if ao.Size == BPF_W {
		reg = "w"
	}

	return fmt.Sprintf("lock *(%s *)(r%s %s %d) |= %s%s", ao.Size, ao.Dest, sign, offset, reg, ao.Src)
}

var _ Instruction = (*AtomicXor)(nil)

type AtomicXor struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (ax *AtomicXor) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_XOR)
	if ax.Fetch {
		imm = int32(BPF_XOR | BPF_FETCH)
	}
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(ax.Size) | BPF_ATOMIC,
			Reg: NewReg(ax.Src, ax.Dest),
			Off: ax.Offset,
			Imm: imm,
		},
	}, nil
}

func (ax *AtomicXor) String() string {
	sign := "+"
	offset := ax.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if ax.Size == BPF_W {
		reg = "w"
	}

	return fmt.Sprintf("lock *(%s *)(r%s %s %d) ^= %s%s", ax.Size, ax.Dest, sign, offset, reg, ax.Src)
}

var _ Instruction = (*AtomicExchange)(nil)

type AtomicExchange struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (chg *AtomicExchange) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(chg.Size) | BPF_ATOMIC,
			Reg: NewReg(chg.Src, chg.Dest),
			Off: chg.Offset,
			Imm: int32(BPF_XCHG),
		},
	}, nil
}

func (chg *AtomicExchange) String() string {
	sign := "+"
	offset := chg.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if chg.Size == BPF_W {
		reg = "w"
	}

	// w1 = xchg(r3 + 456, w1)
	return fmt.Sprintf("%s%s = xchg(r%s %s %d, %s%s)", reg, chg.Src, chg.Dest, sign, offset, reg, chg.Src)
}

var _ Instruction = (*AtomicCompareAndExchange)(nil)

type AtomicCompareAndExchange struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (chg *AtomicCompareAndExchange) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(chg.Size) | BPF_ATOMIC,
			Reg: NewReg(chg.Src, chg.Dest),
			Off: chg.Offset,
			Imm: int32(BPF_CMPXCHG),
		},
	}, nil
}

func (chg *AtomicCompareAndExchange) String() string {
	sign := "+"
	offset := chg.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	reg := "r"
	if chg.Size == BPF_W {
		reg = "w"
	}

	// r0 = cmpxchg(r3 - 456, r0, r2)
	return fmt.Sprintf(
		"%s0 = cmpxchg(r%s %s %d, %s0, %s%s)",
		reg, chg.Dest, sign, offset, reg, reg, chg.Src,
	)
}
