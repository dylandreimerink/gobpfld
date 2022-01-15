package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Neg32)(nil)

type Neg32 struct {
	ebpf.Neg32
}

func (i *Neg32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Neg32) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(-int32(dv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Neg64)(nil)

type Neg64 struct {
	ebpf.Neg64
}

func (i *Neg64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Neg64) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = dr.Assign(-dv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
