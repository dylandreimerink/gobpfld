package emulator

import (
	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*JumpGreaterThanEqual32)(nil)

type JumpGreaterThanEqual32 struct {
	ebpf.JumpGreaterThanEqual32
}

func (i *JumpGreaterThanEqual32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanEqual32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && uint32(dv) >= uint32(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThanEqual)(nil)

type JumpGreaterThanEqual struct {
	ebpf.JumpGreaterThanEqual
}

func (i *JumpGreaterThanEqual) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanEqual) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if isIMM(dr) && uint64(dv) >= uint64(i.Value) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThanEqualRegister32)(nil)

type JumpGreaterThanEqualRegister32 struct {
	ebpf.JumpGreaterThanEqualRegister32
}

func (i *JumpGreaterThanEqualRegister32) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanEqualRegister32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && uint32(dv) >= uint32(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}

var _ Instruction = (*JumpGreaterThanEqualRegister)(nil)

type JumpGreaterThanEqualRegister struct {
	ebpf.JumpGreaterThanEqualRegister
}

func (i *JumpGreaterThanEqualRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *JumpGreaterThanEqualRegister) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sameRVType(dr, sr) && uint64(dv) >= uint64(sv) {
		vm.Registers.PC += int(i.Offset)
	}

	return nil
}
