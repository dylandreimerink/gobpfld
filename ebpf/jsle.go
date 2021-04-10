package ebpf

import "fmt"

var _ Instruction = (*JumpSignedSmallerThanOrEqual)(nil)

type JumpSignedSmallerThanOrEqual struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpSignedSmallerThanOrEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpSignedSmallerThanOrEqual) String() string {
	return fmt.Sprintf("if (s64)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThanOrEqual32)(nil)

type JumpSignedSmallerThanOrEqual32 struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpSignedSmallerThanOrEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpSignedSmallerThanOrEqual32) String() string {
	return fmt.Sprintf("if (s32)%s <= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThanOrEqualRegister)(nil)

type JumpSignedSmallerThanOrEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedSmallerThanOrEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedSmallerThanOrEqualRegister) String() string {
	return fmt.Sprintf("if (s64)%s <= (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpSignedSmallerThanOrEqualRegister32)(nil)

type JumpSignedSmallerThanOrEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedSmallerThanOrEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSLE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedSmallerThanOrEqualRegister32) String() string {
	return fmt.Sprintf("if (s32)%s <= (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
