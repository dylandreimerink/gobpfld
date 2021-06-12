package ebpf

import "fmt"

var _ Instruction = (*Mod32)(nil)

type Mod32 struct {
	Dest  Register
	Value int32
}

func (a *Mod32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_MOD, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mod32) String() string {
	return fmt.Sprintf("w%s %%= %d", a.Dest, a.Value)
}

var _ Instruction = (*Mod64)(nil)

type Mod64 struct {
	Dest  Register
	Value int32
}

func (a *Mod64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_MOD, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Mod64) String() string {
	return fmt.Sprintf("r%s %%= %d", a.Dest, a.Value)
}

var _ Instruction = (*Mod32Register)(nil)

type Mod32Register struct {
	Dest Register
	Src  Register
}

func (a *Mod32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_MOD, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mod32Register) String() string {
	return fmt.Sprintf("w%s %%= w%d", a.Dest, a.Src)
}

var _ Instruction = (*Mod64Register)(nil)

type Mod64Register struct {
	Dest Register
	Src  Register
}

func (a *Mod64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_MOD, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Mod64Register) String() string {
	return fmt.Sprintf("r%s %%= r%s", a.Dest, a.Src)
}
