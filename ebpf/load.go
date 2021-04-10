package ebpf

import "fmt"

var _ Instruction = (*LoadConstant)(nil)

type LoadConstant struct {
	Dest Register
	Val  int32
}

func (lc LoadConstant) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_LD | BPF_IMM, Reg: NewReg(0, lc.Dest), Imm: lc.Val},
	}, nil
}

func (lc LoadConstant) String() string {
	return fmt.Sprintf("%s = %d", lc.Dest, lc.Val)
}

var _ Instruction = (*LoadConstant64bit)(nil)

type LoadConstant64bit struct {
	Dest Register
	Src  Register
	Val1 int32
	Val2 int32
}

func (lc LoadConstant64bit) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_LD | uint8(BPF_DW) | BPF_IMM, Reg: NewReg(lc.Src, lc.Dest), Imm: lc.Val1},
		{Op: 0, Reg: 0, Imm: lc.Val2},
	}, nil
}

func (lc LoadConstant64bit) String() string {
	if lc.Src == 1 {
		return fmt.Sprintf("%s = map fd#%d", lc.Dest, lc.Val1)
	}

	if lc.Src == 2 {
		return fmt.Sprintf("%s = map value#%d[%d]", lc.Dest, lc.Val1, lc.Val2)
	}

	return fmt.Sprintf("%s = %d ll", lc.Dest, int64(lc.Val1)<<32+int64(lc.Val2))
}

var _ Instruction = (*LoadRegister)(nil)

type LoadRegister struct {
	Dest Register
	Src  Register
}

func (lr LoadRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_LDX | BPF_IMM, Reg: NewReg(lr.Src, lr.Dest)},
	}, nil
}

func (lr LoadRegister) String() string {
	return fmt.Sprintf("%s = %s", lr.Dest, lr.Src)
}

var _ Instruction = (*LoadMemory)(nil)

type LoadMemory struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (lm LoadMemory) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_LDX | uint8(lm.Size) | BPF_MEM,
			Reg: NewReg(lm.Src, lm.Dest),
			Off: lm.Offset,
		},
	}, nil
}

func (lm LoadMemory) String() string {
	sign := "+"
	offset := lm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("%s = *(%s *) (%s %s %d)", lm.Dest, lm.Size, lm.Src, sign, offset)
}

var _ Instruction = (*LoadSocketBuf)(nil)

type LoadSocketBuf struct {
	Src    Register
	Offset int32
}

func (lm LoadSocketBuf) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_IND | uint8(BPF_W) | BPF_LD,
			Reg: NewReg(lm.Src, 0),
			Imm: lm.Offset,
		},
	}, nil
}

func (lm LoadSocketBuf) String() string {
	sign := "+"
	offset := lm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("R0 = ntohl(*(u32 *) (((struct sk_buff *) R6)->data + %s %s %d))", lm.Src, sign, offset)
}
