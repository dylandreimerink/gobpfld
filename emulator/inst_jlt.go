package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSmallerThan32)(nil)

type JumpSmallerThan32 struct {
	ebpf.JumpSmallerThan32
}

func (i *JumpSmallerThan32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThan32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint32(dv) < uint32(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThan)(nil)

type JumpSmallerThan struct {
	ebpf.JumpSmallerThan
}

func (i *JumpSmallerThan) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThan) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint64(dv) < uint64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThanRegister32)(nil)

type JumpSmallerThanRegister32 struct {
	ebpf.JumpSmallerThanRegister32
}

func (i *JumpSmallerThanRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanRegister32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint32(dv) < uint32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThanRegister)(nil)

type JumpSmallerThanRegister struct {
	ebpf.JumpSmallerThanRegister
}

func (i *JumpSmallerThanRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanRegister) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint64(dv) < uint64(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
