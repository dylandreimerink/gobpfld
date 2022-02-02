package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSignedGreaterThan32)(nil)

type JumpSignedGreaterThan32 struct {
	ebpf.JumpSignedGreaterThan32
}

func (i *JumpSignedGreaterThan32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThan32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv) > i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThan)(nil)

type JumpSignedGreaterThan struct {
	ebpf.JumpSignedGreaterThan
}

func (i *JumpSignedGreaterThan) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThan) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv > int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThanRegister32)(nil)

type JumpSignedGreaterThanRegister32 struct {
	ebpf.JumpSignedGreaterThanRegister32
}

func (i *JumpSignedGreaterThanRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && int32(dv) > int32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThanRegister)(nil)

type JumpSignedGreaterThanRegister struct {
	ebpf.JumpSignedGreaterThanRegister
}

func (i *JumpSignedGreaterThanRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && dv > sv {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
