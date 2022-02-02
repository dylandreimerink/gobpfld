package emulator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
)

type HashMap struct {
	Name    string
	Def     gobpfld.BPFMapDef
	BTFType gobpfld.BTFMap

	// Go can't use slices as map values, so what we do is we sha256 hash the slice which always results in a
	// uniform sized array which we can use as key. Since we now don't index by the actual key, we also need to
	// store the actual key value so we can return k/v pairs

	KeysMap map[[sha256.Size]byte]*ByteMemory
	Values  map[[sha256.Size]byte]*ByteMemory
}

func (m *HashMap) GetName() string {
	return m.Name
}

func (m *HashMap) GetDef() gobpfld.BPFMapDef {
	return m.Def
}

func (m *HashMap) GetType() gobpfld.BTFMap {
	return m.BTFType
}

func (m *HashMap) Init() error {
	m.KeysMap = make(map[[sha256.Size]byte]*ByteMemory)
	m.Values = make(map[[sha256.Size]byte]*ByteMemory)

	// NOTE: we always ignore the BPFMapFlagsNoPreAlloc flag since we never pre-alloc, it is an optimization which
	// we don't need for the current purposes of the emulator.

	return nil
}

func (m *HashMap) Keys() []RegisterValue {
	keys := make([]RegisterValue, len(m.KeysMap))
	i := 0
	for _, val := range m.KeysMap {
		keys[i] = &MemoryPtr{
			Memory: val.Clone(), // Clone since we don't want to give access to a modifyable reference
		}
		i++
	}
	return keys
}

func (m *HashMap) Lookup(key RegisterValue) (RegisterValue, error) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, errMapKeyNoPtr
	}

	keyVal, err := keyPtr.ReadRange(0, int(m.Def.KeySize))
	if !ok {
		return nil, fmt.Errorf("key read range: %w", err)
	}

	keyHash := sha256.Sum256(keyVal)
	value, found := m.Values[keyHash]
	if !found {
		// Return NULL if value doesn't exist
		return newIMM(0), nil
	}

	return &MemoryPtr{Memory: value, Offset: 0}, nil
}

func (m *HashMap) Update(
	key RegisterValue,
	value RegisterValue,
	flags bpfsys.BPFAttrMapElemFlags,
) (
	RegisterValue,
	error,
) {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return nil, errMapKeyNoPtr
	}

	keyVal, err := keyPtr.ReadRange(0, int(m.Def.KeySize))
	if !ok {
		return nil, fmt.Errorf("key read range: %w", err)
	}

	keyHash := sha256.Sum256(keyVal)
	existingValue, found := m.Values[keyHash]
	if !found {
		if len(m.Values)+1 > int(m.Def.MaxEntries) {
			// Exceeding max map size
			return nil, errMapOutOfMemory
		}

		existingValue = &ByteMemory{
			MemName: fmt.Sprintf("%s[0x%s]", m.Name, hex.EncodeToString(keyVal)),
			Backing: make([]byte, m.Def.ValueSize),
		}
	}
	existingKey, found := m.KeysMap[keyHash]
	if !found {
		existingKey = &ByteMemory{
			MemName: hex.EncodeToString(keyVal),
			Backing: make([]byte, m.Def.KeySize),
		}
	}

	valPtr, ok := value.(PointerValue)
	if !ok {
		return nil, errMapValNoPtr
	}

	valVal, err := valPtr.ReadRange(0, int(m.Def.ValueSize))
	if !ok {
		return nil, fmt.Errorf("val read range: %w", err)
	}

	// We can safely assing, valVal is otherwise unreferenced
	existingValue.Backing = valVal
	m.Values[keyHash] = existingValue

	// We can safely assing, valVal is otherwise unreferenced
	existingKey.Backing = keyVal
	m.KeysMap[keyHash] = existingKey

	return newIMM(0), nil
}

func (m *HashMap) Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return errMapKeyNoPtr
	}

	keyVal, err := keyPtr.ReadRange(0, int(m.Def.KeySize))
	if !ok {
		return fmt.Errorf("key read range: %w", err)
	}
	keyHash := sha256.Sum256(keyVal)

	delete(m.KeysMap, keyHash)
	delete(m.Values, keyHash)

	return nil
}
