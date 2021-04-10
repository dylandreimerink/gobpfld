package ebpf

import "fmt"

var _ Instruction = (*JumpIfAnd)(nil)

type JumpIfAnd struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfAnd) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfAnd) String() string {
	return fmt.Sprintf("if (u64)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpIfAnd32)(nil)

type JumpIfAnd32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfAnd32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfAnd32) String() string {
	return fmt.Sprintf("if (u32)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpIfAndRegister)(nil)

type JumpIfAndRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfAndRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfAndRegister) String() string {
	return fmt.Sprintf("if (u64)%s & (u64)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpIfAndRegister32)(nil)

type JumpIfAndRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfAndRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfAndRegister32) String() string {
	return fmt.Sprintf("if (u32)%s & (u32)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}
