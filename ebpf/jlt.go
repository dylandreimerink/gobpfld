package ebpf

import "fmt"

var (
	_ Instruction = (*JumpSmallerThan)(nil)
	_ Jumper      = (*JumpSmallerThan)(nil)
	_ Valuer      = (*JumpSmallerThan)(nil)
)

type JumpSmallerThan struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSmallerThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSmallerThan) String() string {
	return fmt.Sprintf("if r%s < %d goto %+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSmallerThan) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSmallerThan) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSmallerThan32)(nil)
	_ Jumper      = (*JumpSmallerThan32)(nil)
	_ Valuer      = (*JumpSmallerThan32)(nil)
)

type JumpSmallerThan32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSmallerThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSmallerThan32) String() string {
	return fmt.Sprintf("if w%d < %d goto %+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSmallerThan32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSmallerThan32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSmallerThanRegister)(nil)
	_ Jumper      = (*JumpSmallerThanRegister)(nil)
)

type JumpSmallerThanRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSmallerThanRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLT | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSmallerThanRegister) String() string {
	return fmt.Sprintf("if r%s < r%s goto %+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSmallerThanRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpSmallerThanRegister32)(nil)
	_ Jumper      = (*JumpSmallerThanRegister32)(nil)
)

type JumpSmallerThanRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSmallerThanRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLT | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSmallerThanRegister32) String() string {
	return fmt.Sprintf("if w%d < w%d goto %+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSmallerThanRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
