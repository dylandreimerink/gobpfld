package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSignedSmallerThan32)(nil)

type JumpSignedSmallerThan32 struct {
	ebpf.JumpSignedSmallerThan32
}

func (i *JumpSignedSmallerThan32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThan32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv) <= i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedSmallerThan)(nil)

type JumpSignedSmallerThan struct {
	ebpf.JumpSignedSmallerThan
}

func (i *JumpSignedSmallerThan) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThan) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv <= int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedSmallerThanRegister32)(nil)

type JumpSignedSmallerThanRegister32 struct {
	ebpf.JumpSignedSmallerThanRegister32
}

func (i *JumpSignedSmallerThanRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanRegister32) Execute(vm *VM) error {
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

var _ Instruction = (*JumpSignedSmallerThanRegister)(nil)

type JumpSignedSmallerThanRegister struct {
	ebpf.JumpSignedSmallerThanRegister
}

func (i *JumpSignedSmallerThanRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedSmallerThanRegister) Execute(vm *VM) error {
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
