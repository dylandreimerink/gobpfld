package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*CallBPF)(nil)

type CallBPF struct {
	ebpf.CallBPF
}

func (i *CallBPF) Clone() Instruction {
	c := *i
	return &c
}

func (i *CallBPF) Execute(vm *VM) error {
	// Preserve current registers
	vm.PreservedRegisters = append(vm.PreservedRegisters, vm.Registers.Clone())

	// Change R10 to the next stack frame
	vm.Registers.R10 = FramePointer{
		Memory:   &vm.StackFrames[vm.Registers.R10.Index+1],
		Index:    vm.Registers.R10.Index + 1,
		Offset:   0,
		Readonly: true,
	}

	// Wipe the stack frame in case there was any memory from earlier use
	frame, ok := vm.Registers.R10.Memory.(*ValueMemory)
	if !ok {
		panic("r10 != *ValueMemory")
	}

	for i := range frame.Mapping {
		frame.Mapping[i] = nil
	}

	// Change the program counter to the function.
	vm.Registers.PC += int(i.Offset)

	return nil
}
