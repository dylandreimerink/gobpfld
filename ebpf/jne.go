package ebpf

import "fmt"

var _ Instruction = (*JumpIfNotEqual)(nil)

type JumpIfNotEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfNotEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfNotEqual) String() string {
	return fmt.Sprintf("if %s != %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpIfNotEqual32)(nil)

type JumpIfNotEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfNotEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfNotEqual32) String() string {
	return fmt.Sprintf("if %s != %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpIfNotEqualRegister)(nil)

type JumpIfNotEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfNotEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfNotEqualRegister) String() string {
	return fmt.Sprintf("if %s != %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpIfNotEqualRegister32)(nil)

type JumpIfNotEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfNotEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfNotEqualRegister32) String() string {
	return fmt.Sprintf("if %s != %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
