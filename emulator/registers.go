package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// Registers the registers of the eBPF VM
// https://github.com/torvalds/linux/blob/master/Documentation/bpf/instruction-set.rst#Registers-and-calling-convention
//
// R0 - R5 are scratch Registers and eBPF programs needs to spill/fill them if necessary across calls.
type Registers struct {
	// Program counter, keeps track of which instruction to execute next, can't be read, only be modified
	// via branching instructions.
	PC int
	// Program index, keeps track of which program we are executing.
	PI int
	// Stack frame number of the current stack frame, increments when we tailcall or do a bpf-to-bpf function call
	// and decrements after we return from a bpf-to-bpf function call.
	SF int

	// return value from function calls, and exit value for eBPF programs
	R0 RegisterValue

	// arguments for function calls
	R1 RegisterValue
	R2 RegisterValue
	R3 RegisterValue
	R4 RegisterValue
	R5 RegisterValue

	// callee saved registers that function calls will preserve
	R6 RegisterValue
	R7 RegisterValue
	R8 RegisterValue
	R9 RegisterValue

	// read-only frame pointer to access stack
	R10 FramePointer
}

func (r *Registers) Clone() Registers {
	return Registers{
		PC:  r.PC,
		SF:  r.SF,
		R0:  r.R0.Clone(),
		R1:  r.R1.Clone(),
		R2:  r.R2.Clone(),
		R3:  r.R3.Clone(),
		R4:  r.R4.Clone(),
		R5:  r.R5.Clone(),
		R6:  r.R6.Clone(),
		R7:  r.R7.Clone(),
		R8:  r.R8.Clone(),
		R9:  r.R9.Clone(),
		R10: *r.R10.Clone().(*FramePointer),
	}
}

func (r *Registers) Copy(reg ebpf.Register) (RegisterValue, error) {
	switch reg {
	case ebpf.BPF_REG_0:
		return r.R0.Copy(), nil
	case ebpf.BPF_REG_1:
		return r.R1.Copy(), nil
	case ebpf.BPF_REG_2:
		return r.R2.Copy(), nil
	case ebpf.BPF_REG_3:
		return r.R3.Copy(), nil
	case ebpf.BPF_REG_4:
		return r.R4.Copy(), nil
	case ebpf.BPF_REG_5:
		return r.R5.Copy(), nil
	case ebpf.BPF_REG_6:
		return r.R6.Copy(), nil
	case ebpf.BPF_REG_7:
		return r.R7.Copy(), nil
	case ebpf.BPF_REG_8:
		return r.R8.Copy(), nil
	case ebpf.BPF_REG_9:
		return r.R9.Copy(), nil
	case ebpf.BPF_REG_10:
		return r.R10.Copy(), nil
	}

	return nil, fmt.Errorf("unknown register '%d'", reg)
}

func (r *Registers) Get(reg ebpf.Register) (RegisterValue, error) {
	switch reg {
	case ebpf.BPF_REG_0:
		return r.R0, nil
	case ebpf.BPF_REG_1:
		return r.R1, nil
	case ebpf.BPF_REG_2:
		return r.R2, nil
	case ebpf.BPF_REG_3:
		return r.R3, nil
	case ebpf.BPF_REG_4:
		return r.R4, nil
	case ebpf.BPF_REG_5:
		return r.R5, nil
	case ebpf.BPF_REG_6:
		return r.R6, nil
	case ebpf.BPF_REG_7:
		return r.R7, nil
	case ebpf.BPF_REG_8:
		return r.R8, nil
	case ebpf.BPF_REG_9:
		return r.R9, nil
	}

	return nil, fmt.Errorf("unknown register '%d'", reg)
}

// Assign is used to assign a value to a register directly
func (r *Registers) Assign(reg ebpf.Register, value RegisterValue) error {
	switch reg {
	case ebpf.BPF_REG_0:
		r.R0 = value
	case ebpf.BPF_REG_1:
		r.R1 = value
	case ebpf.BPF_REG_2:
		r.R2 = value
	case ebpf.BPF_REG_3:
		r.R3 = value
	case ebpf.BPF_REG_4:
		r.R4 = value
	case ebpf.BPF_REG_5:
		r.R5 = value
	case ebpf.BPF_REG_6:
		r.R6 = value
	case ebpf.BPF_REG_7:
		r.R7 = value
	case ebpf.BPF_REG_8:
		r.R8 = value
	case ebpf.BPF_REG_9:
		r.R9 = value
	// REG_10 is missing on purpose, it can't be modified by assinging it a value.
	// It is only changed on tail calls an bpf-to-bpf function calls. Such changes are preformed by the instructions
	// directly instread of using this helper
	default:
		return fmt.Errorf("Can't assign register '%d'", reg)
	}

	return nil
}

// RegisterValue represents the contents of a single register. Depending on the implementation a register type might
// carry additional information which is not directly accessible to the eBPF program. The additional type information
// is created and changed depending on where he eBPF program gets the value and what it does with it.
type RegisterValue interface {
	// Value returns the integer value of the register
	Value() int64
	// Copy returns a copy of the register.
	// A copy can have different properties, like being modifyable while the original was not, the stack pointer for
	// example.
	Copy() RegisterValue
	// Clone makes an exact copy of the register, with no differences.
	Clone() RegisterValue
	Assign(int64) error
	String() string
}

// PointerValue is a type of RegisterValue which can be dereferenced.
type PointerValue interface {
	Deref(offset int, size ebpf.Size) (RegisterValue, error)
}

// IMMValue is an immediate value, has no special meaning
type IMMValue int64

func (iv *IMMValue) Value() int64 {
	return int64(*iv)
}

func (iv *IMMValue) Copy() RegisterValue {
	return newIMM(int64(*iv))
}

func (iv *IMMValue) Clone() RegisterValue {
	return newIMM(int64(*iv))
}

func (iv *IMMValue) Assign(v int64) error {
	*iv = IMMValue(v)
	return nil
}

func (iv *IMMValue) String() string {
	return fmt.Sprintf("0x%016x (s%d / u%d)", uint64(*iv), *iv, uint64(*iv))
}

func newIMM(v int64) *IMMValue {
	val := IMMValue(v)
	return &val
}

var _ RegisterValue = (*MemoryPtr)(nil)

// MemoryPtr is a pointer to a particular piece of memory. The eBPF program can't manipulate this pointer once gotten,
// it can only manipulate to offset from the start of the memory. When the pointer is dereferenced a lookup into the
// memory happens at the offset param + the offset property.
type MemoryPtr struct {
	Name   string
	Memory Memory
	Offset int64
}

func (mp *MemoryPtr) Value() int64 {
	return mp.Offset
}

func (mp *MemoryPtr) Deref(offset int, size ebpf.Size) (RegisterValue, error) {
	return mp.Memory.Read(int(mp.Offset)+offset, size)
}

func (mp *MemoryPtr) Copy() RegisterValue {
	return &MemoryPtr{
		Name:   mp.Name,
		Memory: mp.Memory,
		Offset: mp.Offset,
	}
}

func (mp *MemoryPtr) Clone() RegisterValue {
	ptr := &MemoryPtr{
		Name:   mp.Name,
		Memory: mp.Memory.Clone(),
		Offset: mp.Offset,
	}

	return ptr
}

func (mp *MemoryPtr) Assign(v int64) error {
	mp.Offset = v

	return nil
}

func (mp *MemoryPtr) String() string {
	return fmt.Sprintf("%s + %d", mp.Name, mp.Offset)
}

var _ RegisterValue = (*FramePointer)(nil)

// FramePointer is a memory pointer just like the MemoryPointer, the major difference is that a FramePointer will always
// point to a Piece of memory which is part of the stack frame. We have a distinct type for two reasons, first is that
// the frame pointer at R10 is read-only, only copies are writable. Second is that frame pointers always point at the
// end of a block of memory instread of the start.
type FramePointer struct {
	// Slice of the actual underlying memory
	Memory Memory
	// The index of the current stack frame
	Index int
	// Offset into the stack frame
	Offset int64
	// If true, the offset may not be modified
	Readonly bool
}

func (mp *FramePointer) Value() int64 {
	return mp.Offset
}

func (mp *FramePointer) Deref(offset int, size ebpf.Size) (RegisterValue, error) {
	off := mp.Memory.Size() + int(mp.Offset) + offset
	return mp.Memory.Read(off, size)
}

func (mp *FramePointer) Copy() RegisterValue {
	return &FramePointer{
		Memory: mp.Memory,
		Offset: mp.Offset,
		Index:  mp.Index,

		// When a copy of a read only pointer may be written to
		Readonly: false,
	}
}

func (mp *FramePointer) Clone() RegisterValue {
	ptr := &FramePointer{
		Memory:   mp.Memory.Clone(),
		Index:    mp.Index,
		Offset:   mp.Offset,
		Readonly: mp.Readonly,
	}

	return ptr
}

func (mp *FramePointer) Assign(v int64) error {
	if mp.Readonly {
		return errors.New("can't modify a readonly pointer")
	}

	mp.Offset = v

	return nil
}

func (mp *FramePointer) String() string {
	sign := "+"
	offset := mp.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("fp%d %s %d", mp.Index, sign, offset)
}
