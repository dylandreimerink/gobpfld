package ebpf

import "fmt"

var _ Instruction = (*Div32)(nil)

type Div32 struct {
	Dest  Register
	Value int32
}

func (a *Div32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_DIV, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Div32) String() string {
	return fmt.Sprintf("%s /= %d", a.Dest, a.Value)
}

var _ Instruction = (*Div64)(nil)

type Div64 struct {
	Dest  Register
	Value int32
}

func (a *Div64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_DIV, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Div64) String() string {
	return fmt.Sprintf("%s /= %d", a.Dest, a.Value)
}

var _ Instruction = (*Div32Register)(nil)

type Div32Register struct {
	Dest Register
	Src  Register
}

func (a *Div32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_DIV, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Div32Register) String() string {
	return fmt.Sprintf("%s /= %d", a.Dest, a.Src)
}

var _ Instruction = (*Div64Register)(nil)

type Div64Register struct {
	Dest Register
	Src  Register
}

func (a *Div64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_DIV, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Div64Register) String() string {
	return fmt.Sprintf("%s /= %s", a.Dest, a.Src)
}
