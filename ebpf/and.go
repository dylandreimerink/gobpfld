package ebpf

import "fmt"

var _ Instruction = (*And32)(nil)

type And32 struct {
	Dest  Register
	Value int32
}

func (a *And32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_AND, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *And32) String() string {
	return fmt.Sprintf("%s &= %d", a.Dest, a.Value)
}

var _ Instruction = (*And64)(nil)

type And64 struct {
	Dest  Register
	Value int32
}

func (a *And64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_AND, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *And64) String() string {
	return fmt.Sprintf("%s &= %d", a.Dest, a.Value)
}

var _ Instruction = (*And32Register)(nil)

type And32Register struct {
	Dest Register
	Src  Register
}

func (a *And32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_AND, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *And32Register) String() string {
	return fmt.Sprintf("%s &= %d", a.Dest, a.Src)
}

var _ Instruction = (*And64Register)(nil)

type And64Register struct {
	Dest Register
	Src  Register
}

func (a *And64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_AND, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *And64Register) String() string {
	return fmt.Sprintf("%s <<= %s", a.Dest, a.Src)
}
