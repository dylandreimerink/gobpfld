package ebpf

import "fmt"

var _ Instruction = (*Jump)(nil)

type Jump struct {
	Offset int16
}

func (a Jump) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_JA | BPF_JMP, Off: a.Offset},
	}, nil
}

func (a Jump) String() string {
	return fmt.Sprintf("goto pc%+d", a.Offset)
}