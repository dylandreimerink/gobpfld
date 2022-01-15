package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Sub32)(nil)

type Sub32 struct {
	ebpf.Sub32
}

func (i *Sub32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Sub32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) - i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Sub64)(nil)

type Sub64 struct {
	ebpf.Sub64
}

func (i *Sub64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Sub64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv - int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Sub32Register)(nil)

type Sub32Register struct {
	ebpf.Sub32Register
}

func (i *Sub32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Sub32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) - int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Sub64Register)(nil)

type Sub64Register struct {
	ebpf.Sub64Register
}

func (i *Sub64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Sub64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv - sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
