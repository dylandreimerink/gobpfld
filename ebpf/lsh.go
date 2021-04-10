package ebpf

import "fmt"

var _ Instruction = (*Lsh32)(nil)

type Lsh32 struct {
	Dest Register
	Val  int32
}

func (a Lsh32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_K | BPF_LSH, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Lsh32) String() string {
	return fmt.Sprintf("%s <<= %d", a.Dest, a.Val)
}

var _ Instruction = (*Lsh64)(nil)

type Lsh64 struct {
	Dest Register
	Val  int32
}

func (a Lsh64) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_K | BPF_LSH, Reg: NewReg(0, a.Dest), Imm: a.Val},
	}, nil
}

func (a Lsh64) String() string {
	return fmt.Sprintf("%s <<= %d", a.Dest, a.Val)
}

var _ Instruction = (*Lsh32Register)(nil)

type Lsh32Register struct {
	Dest Register
	Src  Register
}

func (a Lsh32Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_X | BPF_LSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Lsh32Register) String() string {
	return fmt.Sprintf("%s <<= %d", a.Dest, a.Src)
}

var _ Instruction = (*Lsh64Register)(nil)

type Lsh64Register struct {
	Dest Register
	Src  Register
}

func (a Lsh64Register) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_X | BPF_LSH, Reg: NewReg(a.Src, a.Dest)},
	}, nil
}

func (a Lsh64Register) String() string {
	return fmt.Sprintf("%s <<= %s", a.Dest, a.Src)
}
