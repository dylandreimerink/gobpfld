package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var errModByZero = errors.New("divide by zero")

var _ Instruction = (*Mod32)(nil)

type Mod32 struct {
	ebpf.Mod32
}

func (i *Mod32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mod32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if i.Value == 0 {
		return errModByZero
	}

	err = r.Assign(int64(int32(rv) % i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mod64)(nil)

type Mod64 struct {
	ebpf.Mod64
}

func (i *Mod64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mod64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if i.Value == 0 {
		return errModByZero
	}

	err = r.Assign(rv % int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mod32Register)(nil)

type Mod32Register struct {
	ebpf.Mod32Register
}

func (i *Mod32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mod32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sv == 0 {
		return errModByZero
	}

	err = dr.Assign(int64(int32(dv) % int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Mod64Register)(nil)

type Mod64Register struct {
	ebpf.Mod64Register
}

func (i *Mod64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Mod64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sv == 0 {
		return errModByZero
	}

	err = dr.Assign(dv % sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
