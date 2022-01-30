package emulator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
)

type HashMapLRU struct {
	Name string
	Def  gobpfld.BPFMapDef

	// Go can't use slices as map values, so what we do is we sha256 hash the slice which always results in a
	// uniform sized array which we can use as key. Since we now don't index by the actual key, we also need to
	// store the actual key value so we can return k/v pairs

	KeysMap map[hashKey]*ByteMemory
	Values  map[hashKey]*ByteMemory

	// Keep track of recent usage. Every time a key is updated or looked up, it is moved to the top of the slice.
	// The bottom most key is thus always the least recently used and will be overwritten if an entry is added to
	// the map while full.
	UsageList []hashKey
}

type hashKey [sha256.Size]byte

func (m *HashMapLRU) GetName() string {
	return m.Name
}

func (m *HashMapLRU) GetDef() gobpfld.BPFMapDef {
	return m.Def
}

func (m *HashMapLRU) Init() error {
	m.KeysMap = make(map[hashKey]*ByteMemory)
	m.Values = make(map[hashKey]*ByteMemory)

	// NOTE: we always ignore the BPFMapFlagsNoPreAlloc flag since we never pre-alloc, it is an optimization which
	// we don't need for the current purposes of the emulator.

	return nil
}

func (m *HashMapLRU) Keys() []RegisterValue {
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

func (m *HashMapLRU) promote(key hashKey) {
	cur := 0
	for i, k := range m.UsageList {
		if k == key {
			cur = i
			break
		}
	}
	// Key not found, or already at the top, nothing to do
	if cur == 0 {
		return
	}

	// Move all keys above cur 1 index down
	copy(m.UsageList[1:cur+1], m.UsageList[:cur])
	// Set cur a index 0
	m.UsageList[0] = key
}

func (m *HashMapLRU) Lookup(key RegisterValue) (RegisterValue, error) {
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

	m.promote(keyHash)

	return &MemoryPtr{Memory: value, Offset: 0}, nil
}

func (m *HashMapLRU) Update(
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
		// If map is full
		if len(m.Values)+1 > int(m.Def.MaxEntries) {
			// Find the least recently used key, and delete it,
			lru := m.UsageList[len(m.UsageList)-1]
			m.delete(lru)
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

	// If the key is new, add it to the usage list
	if !found {
		// Add new key to the usage list
		m.UsageList = append(m.UsageList, keyHash)
	}
	// Promote the key, since it is now the most recently used
	m.promote(keyHash)

	// We can safely assing, valVal is otherwise unreferenced
	existingValue.Backing = valVal
	m.Values[keyHash] = existingValue

	// We can safely assing, valVal is otherwise unreferenced
	existingKey.Backing = keyVal
	m.KeysMap[keyHash] = existingKey

	return newIMM(0), nil
}

func (m *HashMapLRU) delete(key hashKey) {
	cur := -1
	for i, k := range m.UsageList {
		if k == key {
			cur = i
			break
		}
	}
	// Key not found, nothing to do
	if cur == -1 {
		return
	}

	// Move all keys below cur up by 1 spot
	copy(m.UsageList[cur:], m.UsageList[cur+1:])
	// Shrink the slice
	m.UsageList = m.UsageList[:len(m.UsageList)-1]

	delete(m.KeysMap, key)
	delete(m.Values, key)
}

func (m *HashMapLRU) Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error {
	keyPtr, ok := key.(PointerValue)
	if !ok {
		return errMapKeyNoPtr
	}

	keyVal, err := keyPtr.ReadRange(0, int(m.Def.KeySize))
	if !ok {
		return fmt.Errorf("key read range: %w", err)
	}
	keyHash := sha256.Sum256(keyVal)

	m.delete(keyHash)

	return nil
}
