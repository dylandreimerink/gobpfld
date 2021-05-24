package ebpf

import "fmt"

var (
	_ Instruction = (*JumpSmallerThanEqual)(nil)
	_ Jumper      = (*JumpSmallerThanEqual)(nil)
	_ Valuer      = (*JumpSmallerThanEqual)(nil)
)

type JumpSmallerThanEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSmallerThanEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSmallerThanEqual) String() string {
	return fmt.Sprintf("if (u64)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSmallerThanEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSmallerThanEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSmallerThanEqual32)(nil)
	_ Jumper      = (*JumpSmallerThanEqual32)(nil)
	_ Valuer      = (*JumpSmallerThanEqual32)(nil)
)

type JumpSmallerThanEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpSmallerThanEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpSmallerThanEqual32) String() string {
	return fmt.Sprintf("if (u32)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpSmallerThanEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpSmallerThanEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpSmallerThanEqualRegister)(nil)
	_ Jumper      = (*JumpSmallerThanEqualRegister)(nil)
)

type JumpSmallerThanEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSmallerThanEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSmallerThanEqualRegister) String() string {
	return fmt.Sprintf("if (u64)%s <= (u64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSmallerThanEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpSmallerThanEqualRegister32)(nil)
	_ Jumper      = (*JumpSmallerThanEqualRegister32)(nil)
)

type JumpSmallerThanEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpSmallerThanEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JLE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpSmallerThanEqualRegister32) String() string {
	return fmt.Sprintf("if (u32)%s <= (u32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpSmallerThanEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
