package ebpf

import "fmt"

var _ Instruction = (*End32ToLE)(nil)

type End32ToLE struct {
	Dest Register
}

func (a End32ToLE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_LE, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a End32ToLE) String() string {
	return fmt.Sprintf("htole32(%s)", a.Dest)
}

var _ Instruction = (*End64ToLE)(nil)

type End64ToLE struct {
	Dest Register
}

func (a End64ToLE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_END | BPF_TO_LE, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a End64ToLE) String() string {
	return fmt.Sprintf("htole64(%s)", a.Dest)
}

var _ Instruction = (*End32ToLE)(nil)

type End32ToBE struct {
	Dest Register
}

func (a End32ToBE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU | BPF_END | BPF_TO_BE, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a End32ToBE) String() string {
	return fmt.Sprintf("htobe32(%s)", a.Dest)
}

var _ Instruction = (*End64ToLE)(nil)

type End64ToBE struct {
	Dest Register
}

func (a End64ToBE) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_ALU64 | BPF_END | BPF_TO_BE, Reg: NewReg(0, a.Dest)},
	}, nil
}

func (a End64ToBE) String() string {
	return fmt.Sprintf("htobe64(%s)", a.Dest)
}
