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
	// If the call stack is empty, we exit the program
	if len(vm.CallStack) == 0 {
		return errExit
	}

	// If there are values on the call stack, this is a return statement

	pc := vm.CallStack[len(vm.CallStack)-1]
	vm.CallStack = vm.CallStack[:len(vm.CallStack)-1]

	// Restore the stored program counter
	vm.Registers.PC = pc

	// Restore the previous stack frame
	vm.Registers.R10 = FramePointer{
		Memory:   &vm.StackFrames[vm.Registers.R10.Index-1],
		Index:    vm.Registers.R10.Index - 1,
		Offset:   0,
		Readonly: true,
	}

	return nil
}
