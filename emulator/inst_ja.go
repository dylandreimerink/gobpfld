package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Jump)(nil)

type Jump struct {
	ebpf.Jump
}

func (i *Jump) Clone() Instruction {
	c := *i
	return &c
}

func (i *Jump) Execute(vm *VM) error {
	vm.Registers.PC += int(i.Offset)
	return nil
}
