package ebpf

import "fmt"

var _ Instruction = (*JumpGreaterThan)(nil)

type JumpGreaterThan struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpGreaterThan) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpGreaterThan) String() string {
	return fmt.Sprintf("if (u64)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpGreaterThan32)(nil)

type JumpGreaterThan32 struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpGreaterThan32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGT | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpGreaterThan32) String() string {
	return fmt.Sprintf("if (u32)%s > %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpGreaterThanRegister)(nil)

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

var _ Instruction = (*JumpGreaterThanRegister32)(nil)

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
