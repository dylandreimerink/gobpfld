package ebpf

import "fmt"

var (
	_ Instruction = (*JumpIfAnd)(nil)
	_ Jumper      = (*JumpIfAnd)(nil)
	_ Valuer      = (*JumpIfAnd)(nil)
)

type JumpIfAnd struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfAnd) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfAnd) String() string {
	return fmt.Sprintf("if (u64)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpIfAnd) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpIfAnd) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpIfAnd32)(nil)
	_ Jumper      = (*JumpIfAnd32)(nil)
	_ Valuer      = (*JumpIfAnd32)(nil)
)

type JumpIfAnd32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpIfAnd32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpIfAnd32) String() string {
	return fmt.Sprintf("if (u32)%s & %d > 0: goto pc%+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpIfAnd32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpIfAnd32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpIfAndRegister)(nil)
	_ Jumper      = (*JumpIfAndRegister)(nil)
)

type JumpIfAndRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfAndRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfAndRegister) String() string {
	return fmt.Sprintf("if (u64)%s & (u64)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpIfAndRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpIfAndRegister32)(nil)
	_ Jumper      = (*JumpIfAndRegister32)(nil)
)

type JumpIfAndRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpIfAndRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSET | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpIfAndRegister32) String() string {
	return fmt.Sprintf("if (u32)%s & (u32)%s > 0: goto pc%+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpIfAndRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
