package ebpf

import "fmt"

var (
	_ Instruction = (*CallBPF)(nil)
	_ Jumper      = (*CallBPF)(nil)
)

type CallBPF struct {
	Offset int32
}

func (c *CallBPF) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_CALL | BPF_JMP, Reg: NewReg(PSEUDO_CALL, 0), Imm: c.Offset},
	}, nil
}

func (c *CallBPF) String() string {
	return fmt.Sprintf("call %+d", c.Offset)
}

func (c *CallBPF) SetJumpTarget(relAddr int16) {
	c.Offset = int32(relAddr)
}
