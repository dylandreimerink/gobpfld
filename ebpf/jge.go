package ebpf

import "fmt"

var _ Instruction = (*JumpGreaterThanEqual)(nil)

type JumpGreaterThanEqual struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpGreaterThanEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpGreaterThanEqual) String() string {
	return fmt.Sprintf("if (u64)%s >= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpGreaterThanEqual32)(nil)

type JumpGreaterThanEqual32 struct {
	Dest   Register
	Offset int16
	Value  uint32
}

func (a JumpGreaterThanEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: int32(a.Value)},
	}, nil
}

func (a JumpGreaterThanEqual32) String() string {
	return fmt.Sprintf("if (u32)%s >= %d: goto pc%+d", a.Dest, a.Value, a.Offset)
}

var _ Instruction = (*JumpGreaterThanEqualRegister)(nil)

type JumpGreaterThanEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpGreaterThanEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpGreaterThanEqualRegister) String() string {
	return fmt.Sprintf("if (u64)%s >= (u64)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}

var _ Instruction = (*JumpGreaterThanEqualRegister32)(nil)

type JumpGreaterThanEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a JumpGreaterThanEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a JumpGreaterThanEqualRegister32) String() string {
	return fmt.Sprintf("if (u32)%s >= (u32)%s: goto pc%+d", a.Dest, a.Src, a.Offset)
}
