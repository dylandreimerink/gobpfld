package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

type QueueMap struct {
	AbstractMap

	// TODO this is a very slow an inefficient way to implement a queue. Should use a ringbuffer instread
	Values []*ByteMemory
}

func (m *QueueMap) Init() error {
	return nil
}

func (m *QueueMap) Keys() []RegisterValue {
	keys := make([]RegisterValue, len(m.Values))
	for i := range keys {
		imm := newIMM(int64(i))
		keys[i] = &MemoryPtr{
			Memory: &ValueMemory{
				MemName: fmt.Sprintf("%s[%d]", m.Name, m.Def.ValueSize),
				Mapping: []RegisterValue{
					imm,
					imm,
					imm,
					imm,
				},
			},
		}
	}
	return keys
}

func (m *QueueMap) Lookup(key RegisterValue) (RegisterValue, error) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, errMapKeyNoPtr
	}

	keyVal, err := keyPtr.Deref(0, ebpf.BPF_W)
	if !ok {
		return nil, fmt.Errorf("key read range: %w", err)
	}

	keyIndex := int(keyVal.Value())
	if keyIndex < 0 || keyIndex >= len(m.Values) {
		return nil, errMapOutOfMemory
	}

	value := m.Values[keyIndex]

	return &MemoryPtr{Memory: value, Offset: 0}, nil
}

func (m *QueueMap) Push(value RegisterValue, size int64) error {
	valuePtr, ok := value.(PointerValue)
	if !ok {
		return errMapValNoPtr
	}

	valueVal, err := valuePtr.ReadRange(0, int(size))
	if !ok {
		return fmt.Errorf("value read range: %w", err)
	}

	m.Values = append(m.Values, &ByteMemory{
		MemName: fmt.Sprintf("%s[?]", m.Name),
		Backing: valueVal,
	})

	return nil
}

func (m *QueueMap) Pop() (RegisterValue, error) {
	if len(m.Values) == 0 {
		return newIMM(0), nil
	}

	val := m.Values[0]
	copy(m.Values, m.Values[1:])
	m.Values = m.Values[:len(m.Values)-1]

	return &MemoryPtr{
		Memory: val,
	}, nil
}
