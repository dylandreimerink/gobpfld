package ebpf

import "fmt"

var _ Instruction = (*Mul32)(nil)

type Mul32 struct {
	Dest  Register
	Value int32
}

func (a *Mul32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_MUL, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mul32) String() string {
	return fmt.Sprintf("w%s *= %d", a.Dest, a.Value)
}

var _ Instruction = (*Mul64)(nil)

type Mul64 struct {
	Dest  Register
	Value int32
}

func (a *Mul64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_MUL, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mul64) String() string {
	return fmt.Sprintf("r%s *= %d", a.Dest, a.Value)
}

var _ Instruction = (*Mul32Register)(nil)

type Mul32Register struct {
	Dest Register
	Src  Register
}

func (a *Mul32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_MUL, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mul32Register) String() string {
	return fmt.Sprintf("w%s *= w%d", a.Dest, a.Src)
}

var _ Instruction = (*Mul64Register)(nil)

type Mul64Register struct {
	Dest Register
	Src  Register
}

func (a *Mul64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_MUL, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mul64Register) String() string {
	return fmt.Sprintf("r%s *= r%s", a.Dest, a.Src)
}
