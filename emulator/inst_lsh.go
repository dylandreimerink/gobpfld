package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Lsh32)(nil)

type Lsh32 struct {
	ebpf.Lsh32
}

func (i *Lsh32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Lsh32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(uint32(rv) << i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Lsh64)(nil)

type Lsh64 struct {
	ebpf.Lsh64
}

func (i *Lsh64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Lsh64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(uint64(rv) << i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Lsh32Register)(nil)

type Lsh32Register struct {
	ebpf.Lsh32Register
}

func (i *Lsh32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Lsh32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(uint32(dv) << int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Lsh64Register)(nil)

type Lsh64Register struct {
	ebpf.Lsh64Register
}

func (i *Lsh64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Lsh64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(uint64(dv) << sv))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
