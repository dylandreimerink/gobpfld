package emulator

import (
	"encoding/binary"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*End16ToLE)(nil)

type End16ToLE struct {
	ebpf.End16ToLE
}

func (i *End16ToLE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End16ToLE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.LittleEndian.Uint16([]byte{
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*End32ToLE)(nil)

type End32ToLE struct {
	ebpf.End32ToLE
}

func (i *End32ToLE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End32ToLE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.LittleEndian.Uint32([]byte{
		byte(rv >> 24),
		byte(rv >> 16),
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*End64ToLE)(nil)

type End64ToLE struct {
	ebpf.End64ToLE
}

func (i *End64ToLE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End64ToLE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.LittleEndian.Uint64([]byte{
		byte(rv >> 56),
		byte(rv >> 48),
		byte(rv >> 40),
		byte(rv >> 32),
		byte(rv >> 24),
		byte(rv >> 16),
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*End16ToBE)(nil)

type End16ToBE struct {
	ebpf.End16ToBE
}

func (i *End16ToBE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End16ToBE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.BigEndian.Uint16([]byte{
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*End32ToBE)(nil)

type End32ToBE struct {
	ebpf.End32ToBE
}

func (i *End32ToBE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End32ToBE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.BigEndian.Uint32([]byte{
		byte(rv >> 24),
		byte(rv >> 16),
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}

var _ Instruction = (*End64ToBE)(nil)

type End64ToBE struct {
	ebpf.End64ToBE
}

func (i *End64ToBE) Clone() Instruction {
	c := *i
	return &c
}

func (i *End64ToBE) Execute(vm *VM) error {
	rv, r, err := readReg(vm, i.Dest)
	if err != nil {
		return err
	}

	v := binary.BigEndian.Uint64([]byte{
		byte(rv >> 56),
		byte(rv >> 48),
		byte(rv >> 40),
		byte(rv >> 32),
		byte(rv >> 24),
		byte(rv >> 16),
		byte(rv >> 8),
		byte(rv >> 0),
	})

	err = r.Assign(int64(v))
	if err != nil {
		return fmt.Errorf("assign value  %s: %w", i.Dest.String(), err)
	}

	return nil
}
