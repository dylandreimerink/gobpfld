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

func (m *ArrayMap) Lookup(key RegisterValue) (RegisterValue, error) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, fmt.Errorf("key is not a pointer")
	}

	keyValReg, err := keyPtr.Deref(0, ebpf.BPF_W)
	if !ok {
		return nil, fmt.Errorf("key pointer deref: %w", err)
	}

	kv := keyValReg.Value()
	off := kv * int64(m.Def.ValueSize)

	// Outside of map
	if off >= int64(m.Memory.Size()) {
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
		// TODO lookup actual error code used by linux
		return newIMM(-1), nil
	}

	kv := key.Value()
	// Outside of map
	if kv >= int64(m.Memory.Size()) {
		// TODO lookup actual error code used by linux
		return newIMM(-2), nil
	}

	for i := 0; i < int(m.Def.ValueSize); i++ {
		v, err := vPtr.Memory.Read(0, ebpf.BPF_B)
		if err != nil {
			return nil, fmt.Errorf("memory read: %w", err)
		}

		err = m.Memory.Write(int(kv)+i, v, ebpf.BPF_B)
		if err != nil {
			return nil, fmt.Errorf("memory write: %w", err)
		}
	}

	return newIMM(0), nil
}

func (m *ArrayMap) Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error {
	return errors.New("not yet implemented")
}