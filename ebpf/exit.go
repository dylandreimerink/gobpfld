package ebpf

var _ Instruction = (*Exit)(nil)

type Exit struct {
}

func (e Exit) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_EXIT | BPF_JMP, Reg: NewReg(0, 0)},
	}, nil
}

func (e Exit) String() string {
	return "exit"
}
