package ebpf

import "fmt"

var _ Instruction = (*JumpEqual)(nil)

type JumpEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JEQ | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpEqual) String() string {
	return fmt.Sprintf("if %s == %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpEqual32)(nil)

type JumpEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a JumpEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JEQ | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a JumpEqual32) String() string {
	return fmt.Sprintf("if %s == %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpEqualRegister)(nil)

type JumpEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JEQ | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpEqualRegister) String() string {
	return fmt.Sprintf("if %s == %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpEqualRegister32)(nil)

type JumpEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JEQ | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpEqualRegister32) String() string {
	return fmt.Sprintf("if %s == %s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
