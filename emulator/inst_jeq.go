package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpEqual32)(nil)

type JumpEqual32 struct {
	ebpf.JumpEqual32
}

func (i *JumpEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpEqual32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv) == i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpEqual)(nil)

type JumpEqual struct {
	ebpf.JumpEqual
}

func (i *JumpEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpEqual) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv == int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpEqualRegister32)(nil)

type JumpEqualRegister32 struct {
	ebpf.JumpEqualRegister32
}

func (i *JumpEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpEqualRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && int32(dv) == int32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpEqualRegister)(nil)

type JumpEqualRegister struct {
	ebpf.JumpEqualRegister
}

func (i *JumpEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpEqualRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && dv == sv {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
