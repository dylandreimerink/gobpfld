package ebpf

import "fmt"

var (
	_ Instruction = (*JumpNotEqual)(nil)
	_ Jumper      = (*JumpNotEqual)(nil)
	_ Valuer      = (*JumpNotEqual)(nil)
)

type JumpNotEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpNotEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpNotEqual) String() string {
	return fmt.Sprintf("if %s != %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpNotEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpNotEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpNotEqual32)(nil)
	_ Jumper      = (*JumpNotEqual32)(nil)
	_ Valuer      = (*JumpNotEqual32)(nil)
)

type JumpNotEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpNotEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpNotEqual32) String() string {
	return fmt.Sprintf("if %s != %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpNotEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpNotEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpNotEqualRegister)(nil)
	_ Jumper      = (*JumpNotEqualRegister)(nil)
)

type JumpNotEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpNotEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpNotEqualRegister) String() string {
	return fmt.Sprintf("if %s != %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpNotEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpNotEqualRegister32)(nil)
	_ Jumper      = (*JumpNotEqualRegister32)(nil)
)

type JumpNotEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpNotEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JNE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpNotEqualRegister32) String() string {
	return fmt.Sprintf("if %s != %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpNotEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
