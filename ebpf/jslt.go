package ebpf

import "fmt"

var _ Instruction = (*JumpSignedSmallerThan)(nil)

type JumpSignedSmallerThan struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpSignedSmallerThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpSignedSmallerThan) String() string {
	return fmt.Sprintf("if (s64)%s < %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThan32)(nil)

type JumpSignedSmallerThan32 struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpSignedSmallerThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpSignedSmallerThan32) String() string {
	return fmt.Sprintf("if (s32)%s < %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThanRegister)(nil)

type JumpSignedSmallerThanRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedSmallerThanRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLT | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedSmallerThanRegister) String() string {
	return fmt.Sprintf("if (s64)%s < (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThanRegister32)(nil)

type JumpSignedSmallerThanRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedSmallerThanRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLT | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedSmallerThanRegister32) String() string {
	return fmt.Sprintf("if (s32)%s < (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
