package ebpf

import "fmt"

var (
	_ Instruction = (*JumpAnd)(nil)
	_ Jumper      = (*JumpAnd)(nil)
	_ Valuer      = (*JumpAnd)(nil)
)

type JumpAnd struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpAnd) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpAnd) String() string {
	return fmt.Sprintf("if (u64)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpAnd) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpAnd) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpAnd32)(nil)
	_ Jumper      = (*JumpAnd32)(nil)
	_ Valuer      = (*JumpAnd32)(nil)
)

type JumpAnd32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpAnd32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpAnd32) String() string {
	return fmt.Sprintf("if (u32)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpAnd32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpAnd32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpAndRegister)(nil)
	_ Jumper      = (*JumpAndRegister)(nil)
)

type JumpAndRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpAndRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpAndRegister) String() string {
	return fmt.Sprintf("if (u64)%s & (u64)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpAndRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpAndRegister32)(nil)
	_ Jumper      = (*JumpAndRegister32)(nil)
)

type JumpAndRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpAndRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpAndRegister32) String() string {
	return fmt.Sprintf("if (u32)%s & (u32)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpAndRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
