package ebpf

import "fmt"

var _ Instruction = (*Xor32)(nil)

type Xor32 struct {
	Dest  Register
	Value int32
}

func (a *Xor32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_XOR, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Xor32) String() string {
	return fmt.Sprintf("w%s ^= %d", a.Dest, a.Value)
}

var _ Instruction = (*Xor64)(nil)

type Xor64 struct {
	Dest  Register
	Value int32
}

func (a *Xor64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_XOR, Reg: NewReg(0, a.Dest), Imm: a.Value},
	}, nil
}

func (a *Xor64) String() string {
	return fmt.Sprintf("r%s ^= %d", a.Dest, a.Value)
}

var _ Instruction = (*Xor32Register)(nil)

type Xor32Register struct {
	Dest Register
	Src  Register
}

func (a *Xor32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_XOR, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Xor32Register) String() string {
	return fmt.Sprintf("w%s ^= w%d", a.Dest, a.Src)
}

var _ Instruction = (*Xor64Register)(nil)

type Xor64Register struct {
	Dest Register
	Src  Register
}

func (a *Xor64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_XOR, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a *Xor64Register) String() string {
	return fmt.Sprintf("r%s ^= r%s", a.Dest, a.Src)
}
