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
	if i.Src == ebpf.BPF_PSEUDO_MAP_FD {
		return errors.New("maps not yet implemented")
	}

	if i.Src == ebpf.BPF_PSEUDO_MAP_FD_VALUE {
		return errors.New("maps not yet implemented")
	}

	dr, err := vm.Registers.Get(i.Dest)
	if err != nil {
		return fmt.Errorf("get: %w", err)
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
	dr, err := vm.Registers.Get(i.Dest)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	sr, err := vm.Registers.Copy(i.Src)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	var memory []byte
	var off int64
	switch smp := sr.(type) {
	case *MemoryPtr:
		// Memory pointers point to the start of a memory block
		off = smp.Offset + int64(i.Offset)
		memory = smp.Memory

	case *FramePointer:
		// Frame pointers point to the end of a stack frame
		off = int64(len(smp.Memory)) + smp.Offset + int64(i.Offset)
		memory = smp.Memory

	default:
		return fmt.Errorf("can't load from a non-pointer register value")
	}

	if int(off)+i.Size.Bytes() > len(memory) || off < 0 {
		return fmt.Errorf("reading outside of memory bounds")
	}

	var val int64
	switch i.Size {
	case ebpf.BPF_B:
		val = int64(memory[off+0])
	case ebpf.BPF_H:
		val = int64(memory[off+0])<<8 +
			int64(memory[off+1])
	case ebpf.BPF_W:
		val = int64(memory[off+0])<<24 +
			int64(memory[off+1])<<16 +
			int64(memory[off+2])<<8 +
			int64(memory[off+3])
	case ebpf.BPF_DW:
		val = int64(memory[off+0])<<56 +
			int64(memory[off+1])<<48 +
			int64(memory[off+2])<<40 +
			int64(memory[off+3])<<32 +
			int64(memory[off+4])<<24 +
			int64(memory[off+5])<<16 +
			int64(memory[off+6])<<8 +
			int64(memory[off+7])
	}

	err = dr.Assign(val)
	if err != nil {
		return fmt.Errorf("assign value: %w", err)
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
