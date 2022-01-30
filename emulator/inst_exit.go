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
	if len(vm.PreservedRegisters) == 0 {
		return errExit
	}

	// If there are values on the call stack, this is a return statement
	preserved := vm.PreservedRegisters[len(vm.PreservedRegisters)-1]
	vm.PreservedRegisters = vm.PreservedRegisters[:len(vm.PreservedRegisters)-1]

	// Restore preserved Program counter and callee saved registers
	vm.Registers.PC = preserved.PC
	vm.Registers.R6 = preserved.R6
	vm.Registers.R7 = preserved.R7
	vm.Registers.R8 = preserved.R8
	vm.Registers.R9 = preserved.R9

	// Restore the previous stack frame
	vm.Registers.R10 = FramePointer{
		Memory:   &vm.StackFrames[vm.Registers.R10.Index-1],
		Index:    vm.Registers.R10.Index - 1,
		Offset:   0,
		Readonly: true,
	}

	return nil
}
