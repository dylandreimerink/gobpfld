package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSignedSmallerThanOrEqual32)(nil)

type JumpSignedSmallerThanOrEqual32 struct {
	ebpf.JumpSignedSmallerThanOrEqual32
}

func (i *JumpSignedSmallerThanOrEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanOrEqual32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv) <= i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedSmallerThanOrEqual)(nil)

type JumpSignedSmallerThanOrEqual struct {
	ebpf.JumpSignedSmallerThanOrEqual
}

func (i *JumpSignedSmallerThanOrEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanOrEqual) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv <= int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedSmallerThanOrEqualRegister32)(nil)

type JumpSignedSmallerThanOrEqualRegister32 struct {
	ebpf.JumpSignedSmallerThanOrEqualRegister32
}

func (i *JumpSignedSmallerThanOrEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanOrEqualRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && int32(dv) <= int32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedSmallerThanOrEqualRegister)(nil)

type JumpSignedSmallerThanOrEqualRegister struct {
	ebpf.JumpSignedSmallerThanOrEqualRegister
}

func (i *JumpSignedSmallerThanOrEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanOrEqualRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && dv <= sv {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
