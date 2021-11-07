package gobpfld

import (
	"fmt"
	"net"
	"reflect"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*LPMTrieMap)(nil)

// LPMTrieMap is a specialized map type which used Longest Prefix Matching on the key when getting values from the map.
// LPM is commonly used in routing tables or any other application where the most specific network range should
// overrule settings of less specific network ranges.
type LPMTrieMap struct {
	AbstractMap
}

func (m *LPMTrieMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_LPM_TRIE {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_LPM_TRIE when using an LPMTrieMap")
	}

	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrie) {
		return fmt.Errorf("LPM trie map type is not supported by the current kernel version")
	}

	err := m.load()
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
func (m *LPMTrieMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

func (m *LPMTrieMap) Get(key LPMTrieMap, value interface{}) error {
	return m.get(key, value)
}

// GetBatch fills the keys and values array/slice with the keys and values inside the map up to a maximum of
// maxBatchSize entries. The keys and values array/slice must have at least a length of maxBatchSize.
// The key and value of an entry is has the same index, so for example the value for keys[2] is in values[2].
// Count is the amount of entries returns, partial is true if not all elements of keys and values could be set.
//
// This function is intended for small maps which can be read into userspace all at once since
// GetBatch can only read from the beginning of the map. If the map is to large to read all at once
// a iterator should be used instead of the Get or GetBatch function.
func (m *LPMTrieMap) GetBatch(
	keys interface{},
	values interface{},
	maxBatchSize uint32,
) (
	count int,
	partial bool,
	err error,
) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) {
		return 0, false, fmt.Errorf("batch get operation not support on LPM trie map type on current kernel version")
	}

	if err := m.checkLPMKeyBatch(keys); err != nil {
		return 0, false, err
	}

	return m.getBatch(keys, values, maxBatchSize)
}

func (m *LPMTrieMap) checkLPMKeyBatch(keys interface{}) error {
	keyType := reflect.TypeOf(keys)
	if keyType.Kind() != reflect.Ptr {
		return fmt.Errorf("keys argument must be a pointer")
	}

	collection := keyType.Elem()
	var elem reflect.Type

	switch collection.Kind() {
	case reflect.Array:
		elem = collection.Elem()
	case reflect.Slice:
		elem = collection.Elem()
	default:
		return fmt.Errorf("keys argument must be a pointer to an array or slice")
	}

	if !elem.Implements(reflect.TypeOf((LPMTrieKey)(nil))) {
		return fmt.Errorf("keys argument must be a pointer to an array or slice op LPMKey elements")
	}

	return nil
}

func (m *LPMTrieMap) Set(key LPMTrieMap, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	return m.set(key, value, flags)
}

func (m *LPMTrieMap) SetBatch(
	keys interface{},
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) {
		return 0, fmt.Errorf("batch set operation not support on LPM trie map type on current kernel version")
	}

	if err := m.checkLPMKeyBatch(keys); err != nil {
		return 0, err
	}

	return m.setBatch(keys, values, flags, maxBatchSize)
}

func (m *LPMTrieMap) Delete(key LPMTrieMap) error {
	return m.delete(key)
}

func (m *LPMTrieMap) DeleteBatch(
	keys interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) {
		return 0, fmt.Errorf("batch delete operation not support on LPM trie map type on current kernel version")
	}

	if err := m.checkLPMKeyBatch(keys); err != nil {
		return 0, err
	}

	return m.deleteBatch(keys, maxBatchSize)
}

func (m *LPMTrieMap) Iterator() MapIterator {
	// If the kernel doesn't have support for batch lookup, use single lookup
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) {
		return &singleLookupIterator{
			BPFMap: m,
		}
	}

	// If there is no reason not to use the batch lookup iterator, use it
	return &batchLookupIterator{
		BPFMap: m,
	}
}

// LPMKeyFromNetwork converts an net.IPNet struct into an LPMTrieKey
func LPMKeyFromNetwork(n net.IPNet) LPMTrieKey {
	ones, _ := n.Mask.Size()
	if n.IP.To16() == nil {
		key := &LPMTrieIPv4Key{
			Prefix: uint32(ones),
		}
		copy(key.Address[:], n.IP)
		return key
	}

	key := &LPMTrieIPv6Key{
		Prefix: uint32(ones),
	}
	copy(key.Address[:], n.IP)
	return key
}

type LPMTrieKey interface {
	LPMTrieKey()
}

var _ LPMTrieKey = (*LPMTrieIPv4Key)(nil)

type LPMTrieIPv4Key struct {
	Prefix  uint32
	Address [4]byte
}

// LPMTrieKey does nothing, it is just defined so LPMTrieIPv4Key implements LPMTrieKey
func (k *LPMTrieIPv4Key) LPMTrieKey() {}

var _ LPMTrieKey = (*LPMTrieIPv6Key)(nil)

type LPMTrieIPv6Key struct {
	Prefix  uint32
	Address [16]byte
}

// LPMTrieKey does nothing, it is just defined so LPMTrieIPv6Key implements LPMTrieKey
func (k *LPMTrieIPv6Key) LPMTrieKey() {}
