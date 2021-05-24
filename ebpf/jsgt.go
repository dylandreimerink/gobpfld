package ebpf

import "fmt"

var (
	_ Instruction = (*JumpSignedGreaterThan)(nil)
	_ Jumper      = (*JumpSignedGreaterThan)(nil)
	_ Valuer      = (*JumpSignedGreaterThan)(nil)
)

type JumpSignedGreaterThan struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSignedGreaterThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSignedGreaterThan) String() string {
	return fmt.Sprintf("if (s64)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedGreaterThan) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedGreaterThan) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedGreaterThan32)(nil)
	_ Jumper      = (*JumpSignedGreaterThan32)(nil)
	_ Valuer      = (*JumpSignedGreaterThan32)(nil)
)

type JumpSignedGreaterThan32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSignedGreaterThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSignedGreaterThan32) String() string {
	return fmt.Sprintf("if (s32)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSignedGreaterThan32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSignedGreaterThan32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSignedGreaterThanRegister)(nil)
	_ Jumper      = (*JumpSignedGreaterThanRegister)(nil)
)

type JumpSignedGreaterThanRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSignedGreaterThanRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSignedGreaterThanRegister) String() string {
	return fmt.Sprintf("if (s64)%s > (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedGreaterThanRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpSignedGreaterThanRegister32)(nil)
	_ Jumper      = (*JumpSignedGreaterThanRegister32)(nil)
)

type JumpSignedGreaterThanRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSignedGreaterThanRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSignedGreaterThanRegister32) String() string {
	return fmt.Sprintf("if (s32)%s > (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSignedGreaterThanRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
