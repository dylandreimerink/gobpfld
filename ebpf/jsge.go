package ebpf

import "fmt"

var (
	_ Instruction = (*JumpSignedGreaterThanOrEqual)(nil)
	_ Jumper      = (*JumpSignedGreaterThanOrEqual)(nil)
	_ Valuer      = (*JumpSignedGreaterThanOrEqual)(nil)
)

type JumpSignedGreaterThanOrEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpSignedGreaterThanOrEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpSignedGreaterThanOrEqual) String() string {
	return fmt.Sprintf("if (s64)%s >= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedGreaterThanOrEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedGreaterThanOrEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedGreaterThanOrEqual32)(nil)
	_ Jumper      = (*JumpSignedGreaterThanOrEqual32)(nil)
	_ Valuer      = (*JumpSignedGreaterThanOrEqual32)(nil)
)

type JumpSignedGreaterThanOrEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpSignedGreaterThanOrEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpSignedGreaterThanOrEqual32) String() string {
	return fmt.Sprintf("if (s32)%s >= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedGreaterThanOrEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedGreaterThanOrEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedGreaterThanOrEqualRegister)(nil)
	_ Jumper      = (*JumpSignedGreaterThanOrEqualRegister)(nil)
)

type JumpSignedGreaterThanOrEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedGreaterThanOrEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedGreaterThanOrEqualRegister) String() string {
	return fmt.Sprintf("if (s64)%s >= (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedGreaterThanOrEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpSignedGreaterThanOrEqualRegister32)(nil)
	_ Jumper      = (*JumpSignedGreaterThanOrEqualRegister32)(nil)
)

type JumpSignedGreaterThanOrEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedGreaterThanOrEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedGreaterThanOrEqualRegister32) String() string {
	return fmt.Sprintf("if (s32)%s >= (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedGreaterThanOrEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
