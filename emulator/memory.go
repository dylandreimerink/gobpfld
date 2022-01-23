package emulator

import (
	"encoding/binary"
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// Memory represents memory which can be accessed by the eBPF VM.
type Memory interface {
	Name() string
	Read(offset int, size ebpf.Size) (RegisterValue, error)
	Write(offset int, value RegisterValue, size ebpf.Size) error
	Size() int
	Clone() Memory
}

// ValueMemory perserves type information, this is important for the functioning of the VM. Our VM implementation has no
// addessable memory slab in which pointers are assigned, rather in the type information we store pointers to actual
// memory blocks. Therefor, it is important to not lose type information when pointers are written to the stack.
type ValueMemory struct {
	MemName string
	Mapping []RegisterValue
}

func (vm *ValueMemory) Name() string {
	return vm.MemName
}

func (vm *ValueMemory) Read(offset int, size ebpf.Size) (RegisterValue, error) {
	if offset < 0 || offset+size.Bytes() > len(vm.Mapping) {
		return nil, fmt.Errorf("attempt to read outside of stack memory bounds, off %d, size %d", offset, size.Bytes())
	}

	val := vm.Mapping[offset]
	for i := offset; i < offset+size.Bytes(); i++ {
		// Since we store the RegisterValues not the actual bytes, programs are not allowed to read and combine
		// the bytes of stored 2 values. This is likely incorrect behavior anyway.
		if vm.Mapping[i] != val {
			return nil, fmt.Errorf("indicated memory is not one contiguous value")
		}
		// TODO what should we do if the program reads only the upper or lower 32 bits of an 64 bit value for example?
		// should we get the value and bit shift it? Or just error?
	}

	return val, nil
}

func (vm *ValueMemory) Write(offset int, value RegisterValue, size ebpf.Size) error {
	if offset < 0 || offset+size.Bytes() > len(vm.Mapping) {
		return fmt.Errorf("attempt to read outside of stack memory bounds, off %d, size %d", offset, size.Bytes())
	}

	for i := offset; i < offset+size.Bytes(); i++ {
		vm.Mapping[i] = value
	}

	return nil
}

func (vm *ValueMemory) Clone() Memory {
	clone := &ValueMemory{
		Mapping: make([]RegisterValue, len(vm.Mapping)),
	}
	copy(clone.Mapping, vm.Mapping)
	return clone
}

func (vm *ValueMemory) Size() int {
	return len(vm.Mapping)
}

// ByteMemory is a type of memory which is backed by a []byte with no type info, all values read will be IMM.
// Since the bytes may be directly loaded from ELF files with a byte order different from the host, reads and writes
// will happen according to the given byte order.
type ByteMemory struct {
	MemName   string
	ByteOrder binary.ByteOrder
	Backing   []byte
}

func (bm *ByteMemory) Name() string {
	return bm.MemName
}

func (bm *ByteMemory) Read(offset int, size ebpf.Size) (RegisterValue, error) {
	if offset < 0 || offset+size.Bytes() > len(bm.Backing) {
		return nil, fmt.Errorf("attempt to read outside of stack memory bounds, off %d, size %d", offset, size.Bytes())
	}

	if bm.ByteOrder == nil {
		bm.ByteOrder = binary.LittleEndian
	}

	var val int64
	switch size {
	case ebpf.BPF_B:
		val = int64(bm.Backing[offset+0])
	case ebpf.BPF_H:
		val = int64(bm.ByteOrder.Uint16([]byte{
			bm.Backing[offset+0],
			bm.Backing[offset+1],
		}))
	case ebpf.BPF_W:
		val = int64(bm.ByteOrder.Uint32([]byte{
			bm.Backing[offset+0],
			bm.Backing[offset+1],
			bm.Backing[offset+2],
			bm.Backing[offset+3],
		}))
	case ebpf.BPF_DW:
		val = int64(bm.ByteOrder.Uint64([]byte{
			bm.Backing[offset+0],
			bm.Backing[offset+1],
			bm.Backing[offset+2],
			bm.Backing[offset+3],
			bm.Backing[offset+4],
			bm.Backing[offset+5],
			bm.Backing[offset+6],
			bm.Backing[offset+7],
		}))
	}

	return newIMM(val), nil
}

func (bm *ByteMemory) Write(offset int, value RegisterValue, size ebpf.Size) error {
	if offset < 0 || offset+size.Bytes() > len(bm.Backing) {
		return fmt.Errorf("attempt to read outside of stack memory bounds, off %d, size %d", offset, size.Bytes())
	}

	if bm.ByteOrder == nil {
		bm.ByteOrder = binary.LittleEndian
	}

	v := value.Value()

	switch size {
	case ebpf.BPF_B:
		bm.Backing[offset] = byte(v)
	case ebpf.BPF_H:
		bm.ByteOrder.PutUint16(bm.Backing[offset:offset+2], uint16(v))
	case ebpf.BPF_W:
		bm.ByteOrder.PutUint32(bm.Backing[offset:offset+4], uint32(v))
	case ebpf.BPF_DW:
		bm.ByteOrder.PutUint64(bm.Backing[offset:offset+8], uint64(v))
	}

	return nil
}

func (bm *ByteMemory) Clone() Memory {
	clone := &ByteMemory{
		Backing: make([]byte, len(bm.Backing)),
	}
	copy(clone.Backing, bm.Backing)
	return clone
}

func (bm *ByteMemory) Size() int {
	return len(bm.Backing)
}
