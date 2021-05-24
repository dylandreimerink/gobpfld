package ebpf

import "fmt"

var (
	_ Instruction = (*JumpSignedSmallerThanOrEqual)(nil)
	_ Jumper      = (*JumpSignedSmallerThanOrEqual)(nil)
	_ Valuer      = (*JumpSignedSmallerThanOrEqual)(nil)
)

type JumpSignedSmallerThanOrEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSignedSmallerThanOrEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSignedSmallerThanOrEqual) String() string {
	return fmt.Sprintf("if (s64)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedSmallerThanOrEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedSmallerThanOrEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedSmallerThanOrEqual32)(nil)
	_ Jumper      = (*JumpSignedSmallerThanOrEqual32)(nil)
	_ Valuer      = (*JumpSignedSmallerThanOrEqual32)(nil)
)

type JumpSignedSmallerThanOrEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSignedSmallerThanOrEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSignedSmallerThanOrEqual32) String() string {
	return fmt.Sprintf("if (s32)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedSmallerThanOrEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedSmallerThanOrEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedSmallerThanOrEqualRegister)(nil)
	_ Jumper      = (*JumpSignedSmallerThanOrEqualRegister)(nil)
)

type JumpSignedSmallerThanOrEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSignedSmallerThanOrEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSignedSmallerThanOrEqualRegister) String() string {
	return fmt.Sprintf("if (s64)%s <= (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedSmallerThanOrEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpSignedSmallerThanOrEqualRegister32)(nil)
	_ Jumper      = (*JumpSignedSmallerThanOrEqualRegister32)(nil)
)

type JumpSignedSmallerThanOrEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSignedSmallerThanOrEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSignedSmallerThanOrEqualRegister32) String() string {
	return fmt.Sprintf("if (s32)%s <= (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedSmallerThanOrEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
