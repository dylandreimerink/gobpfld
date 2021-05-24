package ebpf

import "fmt"

var _ Instruction = (*Neg32)(nil)

type Neg32 struct {
	Dest Register
}

func (a *Neg32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_NEG, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a *Neg32) String() string {
	return fmt.Sprintf("!%s", a.Dest)
}

var _ Instruction = (*Neg64)(nil)

type Neg64 struct {
	Dest Register
}

func (a *Neg64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_NEG, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a *Neg64) String() string {
	return fmt.Sprintf("!%s", a.Dest)
}
