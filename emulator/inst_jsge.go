package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpSignedGreaterThanOrEqual32)(nil)

type JumpSignedGreaterThanOrEqual32 struct {
	ebpf.JumpSignedGreaterThanOrEqual32
}

func (i *JumpSignedGreaterThanOrEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanOrEqual32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv) >= i.Value {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThanOrEqual)(nil)

type JumpSignedGreaterThanOrEqual struct {
	ebpf.JumpSignedGreaterThanOrEqual
}

func (i *JumpSignedGreaterThanOrEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanOrEqual) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv >= int64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThanOrEqualRegister32)(nil)

type JumpSignedGreaterThanOrEqualRegister32 struct {
	ebpf.JumpSignedGreaterThanOrEqualRegister32
}

func (i *JumpSignedGreaterThanOrEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanOrEqualRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && int32(dv) >= int32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpSignedGreaterThanOrEqualRegister)(nil)

type JumpSignedGreaterThanOrEqualRegister struct {
	ebpf.JumpSignedGreaterThanOrEqualRegister
}

func (i *JumpSignedGreaterThanOrEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpSignedGreaterThanOrEqualRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && dv >= sv {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
