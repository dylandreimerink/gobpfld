package ebpf

import "fmt"

var _ Instruction = (*Mov32)(nil)

type Mov32 struct {
	Dest  Register
	Value int32
}

func (a *Mov32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_MOV, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mov32) String() string {
	return fmt.Sprintf("%s = %d", a.Dest, a.Value)
}

var _ Instruction = (*Mov64)(nil)

type Mov64 struct {
	Dest  Register
	Value int32
}

func (a *Mov64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_MOV, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mov64) String() string {
	return fmt.Sprintf("%s = %d", a.Dest, a.Value)
}

var _ Instruction = (*Mov32Register)(nil)

type Mov32Register struct {
	Dest Register
	Src  Register
}

func (a *Mov32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_MOV, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mov32Register) String() string {
	return fmt.Sprintf("%s = %d", a.Dest, a.Src)
}

var _ Instruction = (*Mov64Register)(nil)

type Mov64Register struct {
	Dest Register
	Src  Register
}

func (a *Mov64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_MOV, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mov64Register) String() string {
	return fmt.Sprintf("%s = %s", a.Dest, a.Src)
}
