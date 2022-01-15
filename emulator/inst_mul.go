package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Mul32)(nil)

type Mul32 struct {
	ebpf.Mul32
}

func (i *Mul32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mul32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) * i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mul64)(nil)

type Mul64 struct {
	ebpf.Mul64
}

func (i *Mul64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mul64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv * int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mul32Register)(nil)

type Mul32Register struct {
	ebpf.Mul32Register
}

func (i *Mul32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mul32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) * int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mul64Register)(nil)

type Mul64Register struct {
	ebpf.Mul64Register
}

func (i *Mul64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mul64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv * sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
