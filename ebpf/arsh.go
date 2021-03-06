package ebpf

import "fmt"

var _ Instruction = (*ARSH32)(nil)

type ARSH32 struct {
	Dest  Register
	Value int32
}

func (a *ARSH32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_ARSH, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *ARSH32) String() string {
	return fmt.Sprintf("w%s s>>= %d", a.Dest, a.Value)
}

var _ Instruction = (*ARSH64)(nil)

type ARSH64 struct {
	Dest  Register
	Value int32
}

func (a *ARSH64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_ARSH, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *ARSH64) String() string {
	return fmt.Sprintf("r%s s>>= %d", a.Dest, a.Value)
}

var _ Instruction = (*ARSH32Register)(nil)

type ARSH32Register struct {
	Dest Register
	Src  Register
}

func (a *ARSH32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_ARSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *ARSH32Register) String() string {
	return fmt.Sprintf("w%s s>>= w%d", a.Dest, a.Src)
}

var _ Instruction = (*ARSH64Register)(nil)

type ARSH64Register struct {
	Dest Register
	Src  Register
}

func (a *ARSH64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_ARSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *ARSH64Register) String() string {
	return fmt.Sprintf("r%s s>>= r%s", a.Dest, a.Src)
}
