package emulator

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

type ArrayMap struct {
	Name          string
	Def           gobpfld.BPFMapDef
	BTFType       gobpfld.BTFMap
	Memory        ByteMemory
	InitialDataBO binary.ByteOrder
	InitialData   map[interface{}]interface{}
}

func (m *ArrayMap) GetName() string {
	return m.Name
}

func (m *ArrayMap) GetDef() gobpfld.BPFMapDef {
	return m.Def
}

func (m *ArrayMap) GetType() gobpfld.BTFMap {
	return m.BTFType
}

func (m *ArrayMap) Init() error {
	m.Memory = ByteMemory{
		MemName: m.Name,
		Backing: make([]byte, m.Def.ValueSize*m.Def.MaxEntries),
	}

	if m.InitialData != nil {
		m.Memory.ByteOrder = m.InitialDataBO

		for k, v := range m.InitialData {
			keyInt, ok := k.(int)
			if !ok {
				return fmt.Errorf("the key type of the initial data must be an int")
			}

			vSlice, ok := v.([]byte)
			if !ok {
				return fmt.Errorf("the value type of the initial data must be an []byte")
			}

			copy(m.Memory.Backing[keyInt*int(m.Def.ValueSize):], vSlice)
		}
	}

	return nil
}

func (m *ArrayMap) Keys() []RegisterValue {
	keys := make([]RegisterValue, m.Def.MaxEntries)
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

func (m *ArrayMap) Lookup(key RegisterValue) (RegisterValue, error) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, errMapKeyNoPtr
	}

	keyValReg, err := keyPtr.Deref(0, ebpf.BPF_W)
	if !ok {
		return nil, fmt.Errorf("key pointer deref: %w", err)
	}

	kv := keyValReg.Value()
	off := kv * int64(m.Def.ValueSize)

	// Outside of map
	if off >= int64(m.Memory.Size()) {
		// Return NULL if key out of bounds
		// https://elixir.bootlin.com/linux/v5.16.4/source/kernel/bpf/arraymap.c#L164
		return newIMM(0), nil
	}

	return &MemoryPtr{Memory: &m.Memory, Offset: off}, nil
}

func (m *ArrayMap) Update(
	key RegisterValue,
	value RegisterValue,
	flags bpfsys.BPFAttrMapElemFlags,
) (
	RegisterValue,
	error,
) {
	vPtr, ok := value.(*MemoryPtr)
	if !ok {
		return nil, errMapValNoPtr
	}

	keyPtr, ok := key.(*MemoryPtr)
	if !ok {
		return nil, errMapValNoPtr
	}

	keyVar, err := keyPtr.Deref(0, ebpf.BPF_W)
	if err != nil {
		return nil, err
	}

	kv := keyVar.Value()
	// Outside of map
	if kv >= int64(m.Memory.Size()) {
		return nil, errMapOutOfMemory
	}

	for i := 0; i < int(m.Def.ValueSize); i++ {
		v, err := vPtr.Memory.Read(i, ebpf.BPF_B)
		if err != nil {
			return nil, fmt.Errorf("memory read: %w", err)
		}

		err = m.Memory.Write(int(kv*int64(m.Def.ValueSize))+i, v, ebpf.BPF_B)
		if err != nil {
			return nil, fmt.Errorf("memory write: %w", err)
		}
	}

	return newIMM(0), nil
}

func (m *ArrayMap) Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error {
	return errors.New("not yet implemented")
}
