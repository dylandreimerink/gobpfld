package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

// PerfEventArray is the emulated implementation of BPF_MAP_TYPE_PERF_EVENT_ARRAY. In linux this is a pseudo map type
// which is not actually a map, rater a way to one-way data stream using the perf sub system. The userspace program
// would have to consume data while it is being produced or risk losing data if the buffer is full.
//
// This emulated map type has to be consumed by the caller of virtual machine, the event data is stored in a slice
// which is currently unlimited in size, it can be read and consumed just like an array map.
type PerfEventArray struct {
	Name    string
	Def     gobpfld.BPFMapDef
	BTFType gobpfld.BTFMap

	Events [][]byte
}

func (m *PerfEventArray) GetName() string {
	return m.Name
}

func (m *PerfEventArray) GetDef() gobpfld.BPFMapDef {
	return m.Def
}

func (m *PerfEventArray) GetType() gobpfld.BTFMap {
	return m.BTFType
}

func (m *PerfEventArray) Init() error {
	return nil
}

func (m *PerfEventArray) Keys() []RegisterValue {
	keys := make([]RegisterValue, len(m.Events))
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

func (m *PerfEventArray) Lookup(key RegisterValue) (RegisterValue, error) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, errMapKeyNoPtr
	}

	keyValReg, err := keyPtr.Deref(0, ebpf.BPF_W)
	if !ok {
		return nil, fmt.Errorf("key pointer deref: %w", err)
	}

	kv := keyValReg.Value()
	if int(kv) >= len(m.Events) {
		return newIMM(0), nil
	}

	return &MemoryPtr{Memory: &ByteMemory{
		MemName: fmt.Sprintf("%s[%d]", m.Name, kv),
		Backing: m.Events[kv],
	}, Offset: 0}, nil
}

func (m *PerfEventArray) Update(
	key RegisterValue,
	value RegisterValue,
	flags bpfsys.BPFAttrMapElemFlags,
) (
	RegisterValue,
	error,
) {
	// Not allowed to update values, since this kind of map is a sort of stream, not an actual map
	return nil, errMapNotImplemented
}

func (m *PerfEventArray) Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return errMapKeyNoPtr
	}

	keyValReg, err := keyPtr.Deref(0, ebpf.BPF_W)
	if !ok {
		return fmt.Errorf("key pointer deref: %w", err)
	}

	kv := keyValReg.Value()
	if int(kv) >= len(m.Events) {
		return nil
	}

	copy(m.Events[kv:], m.Events[kv+1:])
	m.Events = m.Events[:len(m.Events)-1]

	return nil
}

func (m *PerfEventArray) Push(value RegisterValue, size int64) error {
	valuePtr, ok := value.(PointerValue)
	if !ok {
		return errMapKeyNoPtr
	}

	val, err := valuePtr.ReadRange(0, int(size))
	if !ok {
		return fmt.Errorf("value pointer read range: %w", err)
	}

	m.Events = append(m.Events, val)

	return nil
}
