package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpNotEqual32)(nil)

type JumpNotEqual32 struct {
	ebpf.JumpNotEqual32
}

func (i *JumpNotEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpNotEqual32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if !isIMM(dr) || int32(dv) != i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpNotEqual)(nil)

type JumpNotEqual struct {
	ebpf.JumpNotEqual
}

func (i *JumpNotEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpNotEqual) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if !isIMM(dr) || dv != int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpNotEqualRegister32)(nil)

type JumpNotEqualRegister32 struct {
	ebpf.JumpNotEqualRegister32
}

func (i *JumpNotEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpNotEqualRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if !sameRVType(dr, sr) || int32(dv) != int32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpNotEqualRegister)(nil)

type JumpNotEqualRegister struct {
	ebpf.JumpNotEqualRegister
}

func (i *JumpNotEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpNotEqualRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if !sameRVType(dr, sr) || dv != sv {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
