package emulator

import (
	"errors"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Exit)(nil)

type Exit struct {
	ebpf.Exit
}

var errExit = errors.New("function/program exit")

func (i *Exit) Clone() Instruction {
	c := *i
	return &c
}

func (i *Exit) Execute(vm *VM) error {
	return errExit
}
