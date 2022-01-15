package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Or32)(nil)

type Or32 struct {
	ebpf.Or32
}

func (i *Or32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Or32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) | i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Or64)(nil)

type Or64 struct {
	ebpf.Or64
}

func (i *Or64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Or64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv | int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Or32Register)(nil)

type Or32Register struct {
	ebpf.Or32Register
}

func (i *Or32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Or32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) | int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Or64Register)(nil)

type Or64Register struct {
	ebpf.Or64Register
}

func (i *Or64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Or64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv | sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
