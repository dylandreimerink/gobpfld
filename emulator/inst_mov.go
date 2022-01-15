package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Mov32)(nil)

type Mov32 struct {
	ebpf.Mov32
}

func (i *Mov32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mov32) Execute(vm *VM) error {
	// TODO is this correct, or should we preseve the upper 32 bits?
	err := vm.Registers.Assign(i.Dest, newIMM(int64(i.Value)))
	if err != nil {
		return fmt.Errorf("assign %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mov64)(nil)

type Mov64 struct {
	ebpf.Mov64
}

func (i *Mov64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mov64) Execute(vm *VM) error {
	err := vm.Registers.Assign(i.Dest, newIMM(int64(i.Value)))
	if err != nil {
		return fmt.Errorf("assign %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mov32Register)(nil)

type Mov32Register struct {
	ebpf.Mov32Register
}

func (i *Mov32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mov32Register) Execute(vm *VM) error {
	dr, err := vm.Registers.Copy(i.Src)
	if err != nil {
		return fmt.Errorf("read %s: %w", i.Dest.String(), err)
	}

	// TODO is this correct, or should we preseve the upper 32 bits?
	err = vm.Registers.Assign(i.Dest, dr)
	if err != nil {
		return fmt.Errorf("assign %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mov64Register)(nil)

type Mov64Register struct {
	ebpf.Mov64Register
}

func (i *Mov64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mov64Register) Execute(vm *VM) error {
	dr, err := vm.Registers.Copy(i.Src)
	if err != nil {
		return fmt.Errorf("read %s: %w", i.Dest.String(), err)
	}

	err = vm.Registers.Assign(i.Dest, dr)
	if err != nil {
		return fmt.Errorf("assign %s: %w", i.Dest.String(), err)
	}

	return nil
}
