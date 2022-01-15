package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var errDivByZero = errors.New("divide by zero")

var _ Instruction = (*Div32)(nil)

type Div32 struct {
	ebpf.Div32
}

func (i *Div32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Div32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if i.Value == 0 {
		return errDivByZero
	}

	err = r.Assign(int64(int32(rv) / i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Div64)(nil)

type Div64 struct {
	ebpf.Div64
}

func (i *Div64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Div64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	if i.Value == 0 {
		return errDivByZero
	}

	err = r.Assign(rv / int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Div32Register)(nil)

type Div32Register struct {
	ebpf.Div32Register
}

func (i *Div32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Div32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sv == 0 {
		return errDivByZero
	}

	err = dr.Assign(int64(int32(dv) / int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Div64Register)(nil)

type Div64Register struct {
	ebpf.Div64Register
}

func (i *Div64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Div64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	if sv == 0 {
		return errDivByZero
	}

	err = dr.Assign(dv / sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
