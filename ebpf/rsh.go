package ebpf

import "fmt"

var _ Instruction = (*Rsh32)(nil)

type Rsh32 struct {
	Dest  Register
	Value int32
}

func (a *Rsh32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_RSH, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Rsh32) String() string {
	return fmt.Sprintf("%s >>= %d", a.Dest, a.Value)
}

var _ Instruction = (*Rsh64)(nil)

type Rsh64 struct {
	Dest  Register
	Value int32
}

func (a *Rsh64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_RSH, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Rsh64) String() string {
	return fmt.Sprintf("%s >>= %d", a.Dest, a.Value)
}

var _ Instruction = (*Rsh32Register)(nil)

type Rsh32Register struct {
	Dest Register
	Src  Register
}

func (a *Rsh32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_RSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Rsh32Register) String() string {
	return fmt.Sprintf("%s >>= %d", a.Dest, a.Src)
}

var _ Instruction = (*Rsh64Register)(nil)

type Rsh64Register struct {
	Dest Register
	Src  Register
}

func (a *Rsh64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_RSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Rsh64Register) String() string {
	return fmt.Sprintf("%s >>= %s", a.Dest, a.Src)
}
