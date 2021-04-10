package ebpf

import "fmt"

var _ Instruction = (*Add32)(nil)

type Add32 struct {
	Dest Register
	Val  int32
}

func (a Add32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_ADD, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Add32) String() string {
	return fmt.Sprintf("%s += %d", a.Dest, a.Val)
}

var _ Instruction = (*Add64)(nil)

type Add64 struct {
	Dest Register
	Val  int32
}

func (a Add64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_ADD, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Add64) String() string {
	return fmt.Sprintf("%s += %d", a.Dest, a.Val)
}

var _ Instruction = (*Add32Register)(nil)

type Add32Register struct {
	Dest Register
	Src  Register
}

func (a Add32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_ADD, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Add32Register) String() string {
	return fmt.Sprintf("%s += %d", a.Dest, a.Src)
}

var _ Instruction = (*Add64Register)(nil)

type Add64Register struct {
	Dest Register
	Src  Register
}

func (a Add64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_ADD, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Add64Register) String() string {
	return fmt.Sprintf("%s += %s", a.Dest, a.Src)
}