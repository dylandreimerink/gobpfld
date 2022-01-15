package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Rsh32)(nil)

type Rsh32 struct {
	ebpf.Rsh32
}

func (i *Rsh32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Rsh32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(uint32(rv) >> i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Rsh64)(nil)

type Rsh64 struct {
	ebpf.Rsh64
}

func (i *Rsh64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Rsh64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(uint64(rv) >> i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Rsh32Register)(nil)

type Rsh32Register struct {
	ebpf.Rsh32Register
}

func (i *Rsh32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Rsh32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(uint32(dv) >> int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Rsh64Register)(nil)

type Rsh64Register struct {
	ebpf.Rsh64Register
}

func (i *Rsh64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Rsh64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(uint64(dv) >> sv))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
