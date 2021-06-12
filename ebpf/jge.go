package ebpf

import "fmt"

var (
	_ Instruction = (*JumpGreaterThanEqual)(nil)
	_ Jumper      = (*JumpGreaterThanEqual)(nil)
	_ Valuer      = (*JumpGreaterThanEqual)(nil)
)

type JumpGreaterThanEqual struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpGreaterThanEqual) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_K | BPF_JMP, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpGreaterThanEqual) String() string {
	return fmt.Sprintf("if r%s >= %d goto %+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpGreaterThanEqual) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpGreaterThanEqual) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpGreaterThanEqual32)(nil)
	_ Jumper      = (*JumpGreaterThanEqual32)(nil)
	_ Valuer      = (*JumpGreaterThanEqual32)(nil)
)

type JumpGreaterThanEqual32 struct {
	Dest   Register
	Offset int16
	Value  int32
}

func (a *JumpGreaterThanEqual32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_K | BPF_JMP32, Reg: NewReg(0, a.Dest), Off: a.Offset, Imm: a.Value},
	}, nil
}

func (a *JumpGreaterThanEqual32) String() string {
	return fmt.Sprintf("if w%d >= %d goto %+d", a.Dest, a.Value, a.Offset)
}

func (a *JumpGreaterThanEqual32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

func (a *JumpGreaterThanEqual32) SetValue(value int32) {
	a.Value = value
}

var (
	_ Instruction = (*JumpGreaterThanEqualRegister)(nil)
	_ Jumper      = (*JumpGreaterThanEqualRegister)(nil)
)

type JumpGreaterThanEqualRegister struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpGreaterThanEqualRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_X | BPF_JMP, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpGreaterThanEqualRegister) String() string {
	return fmt.Sprintf("if r%s >= r%s goto %+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpGreaterThanEqualRegister) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}

var (
	_ Instruction = (*JumpGreaterThanEqualRegister32)(nil)
	_ Jumper      = (*JumpGreaterThanEqualRegister32)(nil)
)

type JumpGreaterThanEqualRegister32 struct {
	Dest   Register
	Src    Register
	Offset int16
}

func (a *JumpGreaterThanEqualRegister32) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JGE | BPF_X | BPF_JMP32, Reg: NewReg(a.Src, a.Dest), Off: a.Offset},
	}, nil
}

func (a *JumpGreaterThanEqualRegister32) String() string {
	return fmt.Sprintf("if w%d >= w%d goto %+d", a.Dest, a.Src, a.Offset)
}

func (a *JumpGreaterThanEqualRegister32) SetJumpTarget(relAddr int16) {
	a.Offset = relAddr
}
