package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*HashMap)(nil)

// HashMap is a generic map type, both the key and value may be of any type. The value of the key is hashed so values
// do not need to be contiguous.
type HashMap struct {
	AbstractMap
}

func (m *HashMap) Load() error {
	// NOTE: do not enforce definition type of map since hash map is currently still a catch all map type
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
func (m *HashMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

func (m *HashMap) Get(key interface{}, value interface{}) error {
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
func (m *HashMap) GetBatch(
	keys interface{},
	values interface{},
	maxBatchSize uint32,
) (
	count int,
	partial bool,
	err error,
) {
	return m.getBatch(keys, values, maxBatchSize)
}

func (m *HashMap) Set(key interface{}, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	return m.set(key, value, flags)
}

func (m *HashMap) SetBatch(
	keys interface{},
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	return m.setBatch(keys, values, flags, maxBatchSize)
}

func (m *HashMap) Delete(key interface{}) error {
	return m.delete(key)
}

func (m *HashMap) DeleteBatch(
	keys interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	return m.deleteBatch(keys, maxBatchSize)
}

func (m *HashMap) GetAndDelete(key interface{}, value interface{}) error {
	return m.getAndDelete(key, value)
}

func (m *HashMap) GetAndDeleteBatch(
	keys interface{},
	values interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	return m.getAndDeleteBatch(keys, values, maxBatchSize)
}

func (m *HashMap) Iterator() MapIterator {
	// If the kernel doesn't have support for batch lookup, use single lookup
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBatchOps) {
		return &singleLookupIterator{
			BPFMap: m,
		}
	}

	// TODO change batch lookup iterator to support per-cpu values
	if m.isPerCPUMap() {
		return &singleLookupIterator{
			BPFMap: m,
		}
	}

	// If there is no reason not to use the batch lookup iterator, use it
	return &batchLookupIterator{
		BPFMap: m,
	}
}
