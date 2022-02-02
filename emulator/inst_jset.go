package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpAnd32)(nil)

type JumpAnd32 struct {
	ebpf.JumpAnd32
}

func (i *JumpAnd32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpAnd32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && int32(dv)&i.Value == 0 {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpAnd)(nil)

type JumpAnd struct {
	ebpf.JumpAnd
}

func (i *JumpAnd) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpAnd) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && dv&int64(i.Value) == 0 {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpAndRegister32)(nil)

type JumpAndRegister32 struct {
	ebpf.JumpAndRegister32
}

func (i *JumpAndRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpAndRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && int32(dv)&int32(sv) == 0 {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpAndRegister)(nil)

type JumpAndRegister struct {
	ebpf.JumpAndRegister
}

func (i *JumpAndRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpAndRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && dv&sv == 0 {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
