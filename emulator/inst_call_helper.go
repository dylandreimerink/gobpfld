package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*CallHelper)(nil)

type CallHelper struct {
	ebpf.CallHelper
}

func (i *CallHelper) Clone() Instruction {
	c := *i
	return &c
}

func (i *CallHelper) Execute(vm *VM) error {
	if int(i.Function) >= len(vm.HelperFunctions) {
		return fmt.Errorf("VM has no helper function for ID '%d'", i.Function)
	}

	f := vm.HelperFunctions[i.Function]
	if f == nil {
		return fmt.Errorf("VM has no helper function for ID '%d'", i.Function)
	}

	err := f(vm)
	if err != nil {
		return fmt.Errorf("helper function paniced: %w", err)
	}

	return nil
}

var _ Instruction = (*CallHelperIndirect)(nil)

type CallHelperIndirect struct {
	ebpf.CallHelperIndirect
}

func (i *CallHelperIndirect) Clone() Instruction {
	c := *i
	return &c
}

func (i *CallHelperIndirect) Execute(vm *VM) error {
	fReg, err := vm.Registers.Get(i.Register)
	if err != nil {
		return fmt.Errorf("get reg: %w", err)
	}
	fVal := fReg.Value()

	if int(fVal) >= len(vm.HelperFunctions) {
		return fmt.Errorf("VM has no helper function for ID '%d'", fVal)
	}

	f := vm.HelperFunctions[fVal]
	if f == nil {
		return fmt.Errorf("VM has no helper function for ID '%d'", fVal)
	}

	err = f(vm)
	if err != nil {
		return fmt.Errorf("helper function '%d' paniced: %w", fVal, err)
	}

	return nil
}
