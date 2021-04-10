package ebpf

import "fmt"

var _ Instruction = (*JumpSignedGreaterThan)(nil)

type JumpSignedGreaterThan struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpSignedGreaterThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpSignedGreaterThan) String() string {
	return fmt.Sprintf("if (s64)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedGreaterThan32)(nil)

type JumpSignedGreaterThan32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpSignedGreaterThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpSignedGreaterThan32) String() string {
	return fmt.Sprintf("if (s32)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpSignedGreaterThanRegister)(nil)

type JumpSignedGreaterThanRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedGreaterThanRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedGreaterThanRegister) String() string {
	return fmt.Sprintf("if (s64)%s > (s64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpSignedGreaterThanRegister32)(nil)

type JumpSignedGreaterThanRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpSignedGreaterThanRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JSGT | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpSignedGreaterThanRegister32) String() string {
	return fmt.Sprintf("if (s32)%s > (s32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
