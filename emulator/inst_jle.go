package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSmallerThanEqual32)(nil)

type JumpSmallerThanEqual32 struct {
	ebpf.JumpSmallerThanEqual32
}

func (i *JumpSmallerThanEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanEqual32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint32(dv) <= uint32(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThanEqual)(nil)

type JumpSmallerThanEqual struct {
	ebpf.JumpSmallerThanEqual
}

func (i *JumpSmallerThanEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanEqual) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint64(dv) <= uint64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThanEqualRegister32)(nil)

type JumpSmallerThanEqualRegister32 struct {
	ebpf.JumpSmallerThanEqualRegister32
}

func (i *JumpSmallerThanEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanEqualRegister32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint32(dv) <= uint32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSmallerThanEqualRegister)(nil)

type JumpSmallerThanEqualRegister struct {
	ebpf.JumpSmallerThanEqualRegister
}

func (i *JumpSmallerThanEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSmallerThanEqualRegister) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint64(dv) <= uint64(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
