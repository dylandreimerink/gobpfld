package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

var _ BPFMap = (*StackMap)(nil)

// StackMap is a specialized map type, it has no key type, only a value type. It works like any other FILO stack.
type StackMap struct {
	AbstractMap
}

func (m *StackMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_STACK {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_STACK when using an StackMap")
	}

	err := m.load(nil)
	if err != nil {
		return err
	}

	err = mapRegister.add(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return nil
}

// Close closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *StackMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

// Push pushes a new value onto the stack
func (m *StackMap) Push(value interface{}) error {
	return m.set(nil, value, bpfsys.BPFMapElemAny)
}

// Peek peeks at the value at the top of the stack without removing it.
func (m *StackMap) Peek(value interface{}) error {
	return m.get(nil, value)
}

// Pop returns the top value of the stack, removing it in the process.
func (m *StackMap) Pop(value interface{}) error {
	return m.lookupAndDelete(nil, value, bpfsys.BPFMapElemAny)
}

// Iterator returns a map iterator which can be used to loop over all values of the map.
// Looping over the stack will consume all values.
func (m *StackMap) Iterator() MapIterator {
	return &lookupAndDeleteIterator{
		BPFMap: m,
	}
}
