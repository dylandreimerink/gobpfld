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
	sv := newIMM(int64(i.Value))

	dr, err := vm.Registers.Copy(i.Dest)
	if err != nil {
		return fmt.Errorf("copy %s: %w", i.Dest, err)
	}

	var off int64
	var memory Memory
	switch dmp := dr.(type) {
	case *MemoryPtr:
		// Memory pointers point to the start of a memory block
		off = dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	case *FramePointer:
		// Frame pointers point to the end of a stack frame
		off = int64(dmp.Memory.Size()) + dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	default:
		return fmt.Errorf("can't store to a non-pointer register value")
	}

	err = memory.Write(int(off), sv, i.Size)
	if err != nil {
		return fmt.Errorf("memory write: %w", err)
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
	sr, err := vm.Registers.Get(i.Src)
	if err != nil {
		return fmt.Errorf("get %s: %w", i.Src.String(), err)
	}
	sv := sr.Copy()

	dr, err := vm.Registers.Copy(i.Dest)
	if err != nil {
		return fmt.Errorf("copy %s: %w", i.Dest, err)
	}

	var off int64
	var memory Memory
	switch dmp := dr.(type) {
	case *MemoryPtr:
		// Memory pointers point to the start of a memory block
		off = dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	case *FramePointer:
		// Frame pointers point to the end of a stack frame
		off = int64(dmp.Memory.Size()) + dmp.Offset + int64(i.Offset)
		memory = dmp.Memory

	default:
		return fmt.Errorf("can't store to a non-pointer register value")
	}

	err = memory.Write(int(off), sv, i.Size)
	if err != nil {
		return fmt.Errorf("memory write: %w", err)
	}

	return nil
}
