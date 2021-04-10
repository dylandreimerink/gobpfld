package ebpf

import "fmt"

var _ Instruction = (*Sub32)(nil)

type Sub32 struct {
	Dest Register
	Val  int32
}

func (a Sub32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_SUB, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Sub32) String() string {
	return fmt.Sprintf("%s -= %d", a.Dest, a.Val)
}

var _ Instruction = (*Sub64)(nil)

type Sub64 struct {
	Dest Register
	Val  int32
}

func (a Sub64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_SUB, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Sub64) String() string {
	return fmt.Sprintf("%s -= %d", a.Dest, a.Val)
}

var _ Instruction = (*Sub32Register)(nil)

type Sub32Register struct {
	Dest Register
	Src  Register
}

func (a Sub32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_SUB, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Sub32Register) String() string {
	return fmt.Sprintf("%s -= %d", a.Dest, a.Src)
}

var _ Instruction = (*Sub64Register)(nil)

type Sub64Register struct {
	Dest Register
	Src  Register
}

func (a Sub64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_SUB, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Sub64Register) String() string {
	return fmt.Sprintf("%s -= %s", a.Dest, a.Src)
}
