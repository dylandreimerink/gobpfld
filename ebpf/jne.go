package ebpf

import "fmt"

var (
	_ Instruction = (*JumpIfNotEqual)(nil)
	_ Jumper      = (*JumpIfNotEqual)(nil)
	_ Valuer      = (*JumpIfNotEqual)(nil)
)

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

func (a *JumpIfNotEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpIfNotEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpIfNotEqual32)(nil)
	_ Jumper      = (*JumpIfNotEqual32)(nil)
	_ Valuer      = (*JumpIfNotEqual32)(nil)
)

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

func (a *JumpIfNotEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpIfNotEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpIfNotEqualRegister)(nil)
	_ Jumper      = (*JumpIfNotEqualRegister)(nil)
)

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

func (a *JumpIfNotEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpIfNotEqualRegister32)(nil)
	_ Jumper      = (*JumpIfNotEqualRegister32)(nil)
)

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

func (a *JumpIfNotEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
