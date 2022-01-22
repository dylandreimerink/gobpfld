package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*LoadConstant64bit)(nil)

type LoadConstant64bit struct {
	ebpf.LoadConstant64bit
}

func (i *LoadConstant64bit) Clone() Instruction {
	c := *i
	return &c
}

func (i *LoadConstant64bit) Execute(vm *VM) error {
	dr, err := vm.Registers.Get(i.Dest)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	if i.Src == ebpf.BPF_PSEUDO_MAP_FD {
		err = vm.Registers.Assign(i.Dest, newIMM(int64(i.Val1)))
		if err != nil {
			return fmt.Errorf("assign register: %w", err)
		}

		return nil
	}

	if i.Src == ebpf.BPF_PSEUDO_MAP_FD_VALUE {
		// This is a special load instruction which will return an offset into the value of key 0 of a map.
		// It is only used to access ELF data sections.

		if int(i.Val1) >= len(vm.Maps) {
			return fmt.Errorf("no map loaded at index '%d'", i.Val1)
		}

		m := vm.Maps[i.Val1]
		mapValue, err := m.Lookup(&MemoryPtr{Name: "(tmp mem)", Memory: &ByteMemory{Backing: make([]byte, 4)}})
		if err != nil {
			return fmt.Errorf("map lookup: %w", err)
		}

		mapValuePtr, ok := mapValue.(*MemoryPtr)
		if !ok {
			return fmt.Errorf("map lookup didn't return a memory pointer")
		}

		mapValuePtr.Offset = int64(i.Val2)

		err = vm.Registers.Assign(i.Dest, mapValuePtr)
		if err != nil {
			return fmt.Errorf("assign register: %w", err)
		}

		return nil
	}

	err = dr.Assign(int64(i.Val2)<<32 + int64(i.Val1))
	if err != nil {
		return fmt.Errorf("assign value: %w", err)
	}

	return nil
}

var _ Instruction = (*LoadMemory)(nil)

type LoadMemory struct {
	ebpf.LoadMemory
}

func (i *LoadMemory) Clone() Instruction {
	c := *i
	return &c
}

func (i *LoadMemory) Execute(vm *VM) error {
	sr, err := vm.Registers.Copy(i.Src)
	if err != nil {
		return fmt.Errorf("copy %s: %w", i.Dest, err)
	}

	var off int64
	var memory Memory
	switch smp := sr.(type) {
	case *MemoryPtr:
		// Memory pointers point to the start of a memory block
		off = smp.Offset + int64(i.Offset)
		memory = smp.Memory

	case *FramePointer:
		// Frame pointers point to the end of a stack frame
		off = int64(smp.Memory.Size()) + smp.Offset + int64(i.Offset)
		memory = smp.Memory

	default:
		return fmt.Errorf("can't read from a non-pointer register value")
	}

	val, err := memory.Read(int(off), i.Size)
	if err != nil {
		return fmt.Errorf("read from memory: %w", err)
	}

	err = vm.Registers.Assign(i.Dest, val)
	if err != nil {
		return fmt.Errorf("assign '%s': %w", i.Dest, err)
	}

	return nil
}

var _ Instruction = (*LoadSocketBuf)(nil)

type LoadSocketBuf struct {
	ebpf.LoadSocketBuf
}

func (i *LoadSocketBuf) Clone() Instruction {
	c := *i
	return &c
}

func (i *LoadSocketBuf) Execute(vm *VM) error {
	return errors.New("not implemented")
}

var _ Instruction = (*LoadSocketBuf)(nil)

type LoadSocketBufConstant struct {
	ebpf.LoadSocketBufConstant
}

func (i *LoadSocketBufConstant) Clone() Instruction {
	c := *i
	return &c
}

func (i *LoadSocketBufConstant) Execute(vm *VM) error {
	return errors.New("not implemented")
}
