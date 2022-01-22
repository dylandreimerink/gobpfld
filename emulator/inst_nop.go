package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Nop)(nil)

type Nop struct {
	ebpf.Nop
}

func (i *Nop) Clone() Instruction {
	c := *i
	return &c
}

func (i *Nop) Execute(vm *VM) error {
	return nil
}
