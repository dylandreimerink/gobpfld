package ebpf

import "fmt"

var (
	_ Instruction = (*JumpGreaterThan)(nil)
	_ Jumper      = (*JumpGreaterThan)(nil)
	_ Valuer      = (*JumpGreaterThan)(nil)
)

type JumpGreaterThan struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpGreaterThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpGreaterThan) String() string {
	return fmt.Sprintf("if (u64)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpGreaterThan) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpGreaterThan) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpGreaterThan32)(nil)
	_ Jumper      = (*JumpGreaterThan32)(nil)
	_ Valuer      = (*JumpGreaterThan32)(nil)
)

type JumpGreaterThan32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpGreaterThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpGreaterThan32) String() string {
	return fmt.Sprintf("if (u32)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpGreaterThan32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpGreaterThan32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpGreaterThanRegister)(nil)
	_ Jumper      = (*JumpGreaterThanRegister)(nil)
)

type JumpGreaterThanRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpGreaterThanRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpGreaterThanRegister) String() string {
	return fmt.Sprintf("if (u64)%s > (u64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpGreaterThanRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpGreaterThanRegister32)(nil)
	_ Jumper      = (*JumpGreaterThanRegister32)(nil)
)

type JumpGreaterThanRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpGreaterThanRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpGreaterThanRegister32) String() string {
	return fmt.Sprintf("if (u32)%s > (u32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpGreaterThanRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
