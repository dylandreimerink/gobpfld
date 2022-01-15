package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*ARSH32)(nil)

type ARSH32 struct {
	ebpf.ARSH32
}

func (i *ARSH32) Clone() Instruction {
	c := *i
	return &c
}

func (i *ARSH32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) >> i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*ARSH64)(nil)

type ARSH64 struct {
	ebpf.ARSH64
}

func (i *ARSH64) Clone() Instruction {
	c := *i
	return &c
}

func (i *ARSH64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv >> int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*ARSH32Register)(nil)

type ARSH32Register struct {
	ebpf.ARSH32Register
}

func (i *ARSH32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *ARSH32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(int64(int32(dv) >> int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*ARSH64Register)(nil)

type ARSH64Register struct {
	ebpf.ARSH64Register
}

func (i *ARSH64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *ARSH64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	err = dr.Assign(dv >> sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
