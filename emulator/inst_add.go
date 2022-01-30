package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*Add32)(nil)

type Add32 struct {
	ebpf.Add32
}

func (i *Add32) Clone() Instruction {
	c := *i
	return &c
}

func (i *Add32) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(int64(int32(rv) + i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Add64)(nil)

type Add64 struct {
	ebpf.Add64
}

func (i *Add64) Clone() Instruction {
	c := *i
	return &c
}

func (i *Add64) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	err = r.Assign(rv + int64(i.Value))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Add32Register)(nil)

type Add32Register struct {
	ebpf.Add32Register
}

func (i *Add32Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Add32Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	// Edge case: if we add a pointer to a value, we want to convert the destination type into a pointer as well
	if _, ok := sr.(PointerValue); ok {
		scp, err := vm.Registers.Copy(i.Src)
		if err != nil {
			return err
		}

		err = scp.Assign(int64(int32(dv) + int32(sv)))
		if err != nil {
			return err
		}

		err = vm.Registers.Assign(i.Dest, scp)
		if err != nil {
			return err
		}
		return nil
	}

	err = dr.Assign(int64(int32(dv) + int32(sv)))
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*Add64Register)(nil)

type Add64Register struct {
	ebpf.Add64Register
}

func (i *Add64Register) Clone() Instruction {
	c := *i
	return &c
}

func (i *Add64Register) Execute(vm *VM) error {
	dv, dr, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	sv, sr, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}

	// Edge case: if we add a pointer to a value, we want to convert the destination type into a pointer as well
	if _, ok := sr.(PointerValue); ok {
		scp, err := vm.Registers.Copy(i.Src)
		if err != nil {
			return err
		}

		err = scp.Assign(dv + sv)
		if err != nil {
			return err
		}

		err = vm.Registers.Assign(i.Dest, scp)
		if err != nil {
			return err
		}
		return nil
	}

	err = dr.Assign(dv + sv)
	if err != nil {
		return fmt.Errorf("assign value %s: %w", i.Dest.String(), err)
	}

	return nil
}
