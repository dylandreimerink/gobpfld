package ebpf

import "fmt"

var _ Instruction = (*End16ToLE)(nil)

type End16ToLE struct {
	Dest Register
}

func (a *End16ToLE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_LE, Reg: NewReg(0, a.Dest), Imm: 16},
	}, nil
}

func (a *End16ToLE) String() string {
	return fmt.Sprintf("r%s = le16 r%s", a.Dest, a.Dest)
}

var _ Instruction = (*End32ToLE)(nil)

type End32ToLE struct {
	Dest Register
}

func (a *End32ToLE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_LE, Reg: NewReg(0, a.Dest), Imm: 32},
	}, nil
}

func (a *End32ToLE) String() string {
	return fmt.Sprintf("r%s = le32 r%s", a.Dest, a.Dest)
}

var _ Instruction = (*End64ToLE)(nil)

type End64ToLE struct {
	Dest Register
}

func (a *End64ToLE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_LE, Reg: NewReg(0, a.Dest), Imm: 64},
	}, nil
}

func (a *End64ToLE) String() string {
	return fmt.Sprintf("r%s = le64 r%s", a.Dest, a.Dest)
}

var _ Instruction = (*End16ToBE)(nil)

type End16ToBE struct {
	Dest Register
}

func (a *End16ToBE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_BE, Reg: NewReg(0, a.Dest), Imm: 16},
	}, nil
}

func (a *End16ToBE) String() string {
	return fmt.Sprintf("r%s = be16 r%s", a.Dest, a.Dest)
}

var _ Instruction = (*End32ToBE)(nil)

type End32ToBE struct {
	Dest Register
}

func (a *End32ToBE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_BE, Reg: NewReg(0, a.Dest), Imm: 32},
	}, nil
}

func (a *End32ToBE) String() string {
	return fmt.Sprintf("r%s = be32 r%s", a.Dest, a.Dest)
}

var _ Instruction = (*End64ToBE)(nil)

type End64ToBE struct {
	Dest Register
}

func (a *End64ToBE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_BE, Reg: NewReg(0, a.Dest), Imm: 64},
	}, nil
}

func (a *End64ToBE) String() string {
	return fmt.Sprintf("r%s = be64 r%s", a.Dest, a.Dest)
}
