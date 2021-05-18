package ebpf

import "fmt"

var _ Instruction = (*StoreMemoryConstant)(nil)

type StoreMemoryConstant struct {
	Dest   Register
	Size   Size
	Offset int16
	Val    int32
}

func (sm StoreMemoryConstant) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_ST | uint8(sm.Size) | BPF_MEM,
			Reg: NewReg(0, sm.Dest),
			Off: sm.Offset,
			Imm: sm.Val,
		},
	}, nil
}

func (sm StoreMemoryConstant) String() string {
	sign := "+"
	offset := sm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("*(%s *) (%s %s %d) = %d", sm.Size, sm.Dest, sign, offset, sm.Val)
}

var _ Instruction = (*StoreMemoryRegister)(nil)

type StoreMemoryRegister struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (sm StoreMemoryRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(sm.Size) | BPF_MEM,
			Reg: NewReg(sm.Src, sm.Dest),
			Off: sm.Offset,
		},
	}, nil
}

func (sm StoreMemoryRegister) String() string {
	sign := "+"
	offset := sm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("*(%s *) (%s %s %d) = %s", sm.Size, sm.Dest, sign, offset, sm.Src)
}

var _ Instruction = (*AtomicAdd)(nil)

type AtomicAdd struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (aa AtomicAdd) Raw() ([]RawInstruction, error) {
	imm := int32(BPF_ADD)
	if aa.Fetch {
		imm = int32(BPF_ADD | BPF_FETCH)
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

func (aa AtomicAdd) String() string {
	sign := "+"
	offset := aa.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("lock *(%s *)(%s %s %d) += %s", aa.Size, aa.Dest, sign, offset, aa.Src)
}

var _ Instruction = (*AtomicAnd)(nil)

type AtomicAnd struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (aa AtomicAnd) Raw() ([]RawInstruction, error) {
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

func (aa AtomicAnd) String() string {
	sign := "+"
	offset := aa.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("lock *(%s *)(%s %s %d) &= %s", aa.Size, aa.Dest, sign, offset, aa.Src)
}

var _ Instruction = (*AtomicOr)(nil)

type AtomicOr struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (ao AtomicOr) Raw() ([]RawInstruction, error) {
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

func (ao AtomicOr) String() string {
	sign := "+"
	offset := ao.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("lock *(%s *)(%s %s %d) |= %s", ao.Size, ao.Dest, sign, offset, ao.Src)
}

var _ Instruction = (*AtomicXor)(nil)

type AtomicXor struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
	Fetch  bool
}

func (ax AtomicXor) Raw() ([]RawInstruction, error) {
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

func (ax AtomicXor) String() string {
	sign := "+"
	offset := ax.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("lock *(%s *)(%s %s %d) ^= %s", ax.Size, ax.Dest, sign, offset, ax.Src)
}

var _ Instruction = (*AtomicExchange)(nil)

type AtomicExchange struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (chg AtomicExchange) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(chg.Size) | BPF_ATOMIC,
			Reg: NewReg(chg.Src, chg.Dest),
			Off: chg.Offset,
			Imm: int32(BPF_XCHG),
		},
	}, nil
}

func (chg AtomicExchange) String() string {
	sign := "+"
	offset := chg.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("lock %s <=> *(%s *)(%s %s %d)", chg.Src, chg.Size, chg.Dest, sign, offset)
}

var _ Instruction = (*AtomicCompareAndWrite)(nil)

type AtomicCompareAndWrite struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (chg AtomicCompareAndWrite) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(chg.Size) | BPF_ATOMIC,
			Reg: NewReg(chg.Src, chg.Dest),
			Off: chg.Offset,
			Imm: int32(BPF_CMPXCHG),
		},
	}, nil
}

func (chg AtomicCompareAndWrite) String() string {
	sign := "+"
	offset := chg.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf(
		"lock if r0 == *(%s *)(%s %s %d): %s = r0; r0 = %s",
		chg.Size, chg.Dest, sign, offset, chg.Src, chg.Src,
	)
}
