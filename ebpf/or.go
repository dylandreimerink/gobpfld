package ebpf

import "fmt"

var _ Instruction = (*Or32)(nil)

type Or32 struct {
	Dest Register
	Val  int32
}

func (a Or32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_OR, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Or32) String() string {
	return fmt.Sprintf("%s |= %d", a.Dest, a.Val)
}

var _ Instruction = (*Or64)(nil)

type Or64 struct {
	Dest Register
	Val  int32
}

func (a Or64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_OR, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Or64) String() string {
	return fmt.Sprintf("%s |= %d", a.Dest, a.Val)
}

var _ Instruction = (*Or32Register)(nil)

type Or32Register struct {
	Dest Register
	Src  Register
}

func (a Or32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_OR, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Or32Register) String() string {
	return fmt.Sprintf("%s |= %d", a.Dest, a.Src)
}

var _ Instruction = (*Or64Register)(nil)

type Or64Register struct {
	Dest Register
	Src  Register
}

func (a Or64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_OR, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Or64Register) String() string {
	return fmt.Sprintf("%s |= %s", a.Dest, a.Src)
}
