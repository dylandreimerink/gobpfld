package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*StoreMemoryConstant)(nil)

type StoreMemoryConstant struct {
	ebpf.StoreMemoryConstant
}

func (i *StoreMemoryConstant) Clone() Instruction {
	c := *i
	return &c
}

func (i *StoreMemoryConstant) Execute(vm *VM) error {
	dr, err := vm.Registers.Copy(i.Dest)
	if err != nil {
		return fmt.Errorf("read %s: %w", dr.String(), err)
	}

	dmp, ok := dr.(*MemoryPtr)
	if !ok {
		return fmt.Errorf("can't store to a non-pointer register value")
	}

	off := dmp.Offset + int64(i.Offset)
	if int(off)+i.Size.Bytes() >= len(dmp.Memory) {
		return fmt.Errorf("writing outside of memory bounds")
	}

	switch i.Size {
	case ebpf.BPF_B:
		dmp.Memory[off] = byte(i.Value)
	case ebpf.BPF_H:
		dmp.Memory[off] = byte(i.Value >> 8)
		dmp.Memory[off+1] = byte(i.Value >> 0)
	case ebpf.BPF_W:
		dmp.Memory[off] = byte(i.Value >> 24)
		dmp.Memory[off+1] = byte(i.Value >> 16)
		dmp.Memory[off+2] = byte(i.Value >> 8)
		dmp.Memory[off+3] = byte(i.Value >> 0)
	case ebpf.BPF_DW:
		dmp.Memory[off] = 0
		dmp.Memory[off+1] = 0
		dmp.Memory[off+2] = 0
		dmp.Memory[off+3] = 0
		dmp.Memory[off+4] = byte(i.Value >> 24)
		dmp.Memory[off+5] = byte(i.Value >> 16)
		dmp.Memory[off+6] = byte(i.Value >> 8)
		dmp.Memory[off+7] = byte(i.Value >> 0)
	}

	return nil
}

var _ Instruction = (*StoreMemoryRegister)(nil)

type StoreMemoryRegister struct {
	ebpf.StoreMemoryRegister
}

func (i *StoreMemoryRegister) Clone() Instruction {
	c := *i
	return &c
}

func (i *StoreMemoryRegister) Execute(vm *VM) error {
	rv, _, err := readReg(vm, i.Src)
	if err != nil {
		return err
	}
	dr, err := vm.Registers.Copy(i.Dest)
	if err != nil {
		return fmt.Errorf("read %s: %w", dr.String(), err)
	}

	var off int64
	var memory []byte
	switch dmp := dr.(type) {
	case *MemoryPtr:
		// Memory pointers point to the start of a memory block
		off = dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	case *FramePointer:
		// Frame pointers point to the end of a stack frame
		off = int64(len(dmp.Memory)) + dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	default:
		return fmt.Errorf("can't store to a non-pointer register value")
	}

	if int(off)+i.Size.Bytes() > len(memory) || off < 0 {
		return fmt.Errorf("writing outside of memory bounds")
	}

	switch i.Size {
	case ebpf.BPF_B:
		memory[off] = byte(rv)
	case ebpf.BPF_H:
		memory[off] = byte(rv >> 8)
		memory[off+1] = byte(rv >> 0)
	case ebpf.BPF_W:
		memory[off] = byte(rv >> 24)
		memory[off+1] = byte(rv >> 16)
		memory[off+2] = byte(rv >> 8)
		memory[off+3] = byte(rv >> 0)
	case ebpf.BPF_DW:
		memory[off] = byte(rv >> 56)
		memory[off+1] = byte(rv >> 48)
		memory[off+2] = byte(rv >> 40)
		memory[off+3] = byte(rv >> 32)
		memory[off+4] = byte(rv >> 24)
		memory[off+5] = byte(rv >> 16)
		memory[off+6] = byte(rv >> 8)
		memory[off+7] = byte(rv >> 0)
	}

	return nil
}
