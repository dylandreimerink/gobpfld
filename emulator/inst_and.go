package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*And32)(nil)

type And32 struct {
	ebpf.And32
}

func (i *And32) Clone() Instruction {
	c := *i
	return &c
}

func (i *And32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) & i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*And64)(nil)

type And64 struct {
	ebpf.And64
}

func (i *And64) Clone() Instruction {
	c := *i
	return &c
}

func (i *And64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv & int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*And32Register)(nil)

type And32Register struct {
	ebpf.And32Register
}

func (i *And32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *And32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) & int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*And64Register)(nil)

type And64Register struct {
	ebpf.And64Register
}

func (i *And64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *And64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv & sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
