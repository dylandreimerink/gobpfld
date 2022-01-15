package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Xor32)(nil)

type Xor32 struct {
	ebpf.Xor32
}

func (i *Xor32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Xor32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) ^ i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Xor64)(nil)

type Xor64 struct {
	ebpf.Xor64
}

func (i *Xor64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Xor64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv ^ int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Xor32Register)(nil)

type Xor32Register struct {
	ebpf.Xor32Register
}

func (i *Xor32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Xor32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) ^ int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Xor64Register)(nil)

type Xor64Register struct {
	ebpf.Xor64Register
}

func (i *Xor64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Xor64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv ^ sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
