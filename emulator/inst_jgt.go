package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpGreaterThan32)(nil)

type JumpGreaterThan32 struct {
	ebpf.JumpGreaterThan32
}

func (i *JumpGreaterThan32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThan32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint32(dv) > uint32(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThan)(nil)

type JumpGreaterThan struct {
	ebpf.JumpGreaterThan
}

func (i *JumpGreaterThan) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThan) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if uint64(dv) > uint64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThanRegister32)(nil)

type JumpGreaterThanRegister32 struct {
	ebpf.JumpGreaterThanRegister32
}

func (i *JumpGreaterThanRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanRegister32) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint32(dv) > uint32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThanRegister)(nil)

type JumpGreaterThanRegister struct {
	ebpf.JumpGreaterThanRegister
}

func (i *JumpGreaterThanRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanRegister) Execute(vm *VM) error {
	dv, _, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if uint64(dv) > uint64(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
