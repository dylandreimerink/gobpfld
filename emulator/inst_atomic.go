package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

var _ Instruction = (*AtomicAdd)(nil)

type AtomicAdd struct {
	ebpf.AtomicAdd
}

func (i *AtomicAdd) Clone() Instruction {
	c := *i
	return &c
}

func (i *AtomicAdd) Execute(vm *VM) error {
	// TODO make actually atomic using a mutex or similar when adding multi threading support.
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

	dv, err := memory.Read(int(off), i.Size)
	if err != nil {
		return fmt.Errorf("memory read: %w", err)
	}

	sr, err := vm.Registers.Get(i.Src)
	if err != nil {
		return fmt.Errorf("get src: %w", err)
	}

	err = dv.Assign(dv.Value() + sr.Value())
	if err != nil {
		return fmt.Errorf("assign value: %w", err)
	}

	err = memory.Write(int(off), dv, i.Size)
	if err != nil {
		return fmt.Errorf("write dst+src: %w", err)
	}

	return nil
}
