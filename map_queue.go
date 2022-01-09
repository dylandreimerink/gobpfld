package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

var _ BPFMap = (*QueueMap)(nil)

// QueueMap is a specialized map type, it has no key type, only a value type. It works like any other FIFO queue.
type QueueMap struct {
	AbstractMap
}

func (m *QueueMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_QUEUE {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_QUEUE when using an QueueMap")
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
func (m *QueueMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

// Enqueue enqueues a new value
func (m *QueueMap) Enqueue(value interface{}) error {
	return m.set(nil, value, bpfsys.BPFMapElemAny)
}

// Peek peeks at the first value in the queue without removing it.
func (m *QueueMap) Peek(value interface{}) error {
	return m.get(nil, value)
}

// Dequeue returns the value of the from of the queue, removing it in the process.
func (m *QueueMap) Dequeue(value interface{}) error {
	return m.lookupAndDelete(nil, value, bpfsys.BPFMapElemAny)
}

// Iterator returns a map iterator which can be used to loop over all values of the map.
// Looping over the queue will consume all values.
func (m *QueueMap) Iterator() MapIterator {
	return &lookupAndDeleteIterator{
		BPFMap: m,
	}
}
