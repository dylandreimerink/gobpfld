package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*PerCPUArrayMap)(nil)

// PerCPUArrayMap is a map which has a integer key from 0 to MaxEntries. It is a generic map type so the value can be
// any type. This map type stores an array of values for each key, the size of the array is equal to the CPU count
// returned by the runtime.NumCPU() function.
type PerCPUArrayMap struct {
	AbstractMap
}

func (m *PerCPUArrayMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_PERCPU_ARRAY when using an PerCPUArrayMap")
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
func (m *PerCPUArrayMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

func (m *PerCPUArrayMap) Get(key uint32, value interface{}) error {
	return m.get(&key, value)
}

// GetBatch fills the keys slice and values array/slice with the keys and values inside the map.
// The keys slice and values array/slice must have the same length. The key and value of an entry is has the same
// index, so for example the value for keys[2] is in values[2]. Count is the amount of entries returns,
// partial is true if not all elements of keys and values could be set.
//
// This function is intended for small maps which can be read into userspace all at once since
// GetBatch can only read from the beginning of the map. If the map is to large to read all at once
// a iterator should be used instead of the Get or GetBatch function.
func (m *PerCPUArrayMap) GetBatch(
	keys []uint32,
	values interface{},
) (
	count int,
	partial bool,
	err error,
) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapPerCPUArrayBatchOps) {
		return 0,
			false,
			fmt.Errorf("batch get operation not support on Per CPU array map type on current kernel version")
	}

	keysLen := len(keys)

	// Very unlikely, but we have to check
	if keysLen > maxUint32 {
		return 0, false, fmt.Errorf("max len of 'keys' allowed is %d", maxUint32)
	}

	return m.getBatch(&keys, values, uint32(keysLen))
}

func (m *PerCPUArrayMap) Set(key uint32, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	return m.set(&key, value, flags)
}

func (m *PerCPUArrayMap) SetBatch(
	keys []uint32,
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
) (
	count int,
	err error,
) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapPerCPUArrayBatchOps) {
		return 0, fmt.Errorf("batch set operation not support on Per CPU array map type on current kernel version")
	}

	keysLen := len(keys)

	// Very unlikely, but we have to check
	if keysLen > maxUint32 {
		return 0, fmt.Errorf("max len of 'keys' allowed is %d", maxUint32)
	}

	return m.setBatch(&keys, values, flags, uint32(keysLen))
}

func (m *PerCPUArrayMap) Iterator() MapIterator {
	// If the kernel doesn't have support for batch lookup, use single lookup
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapPerCPUArrayBatchOps) {
		return &singleLookupIterator{
			BPFMap: m,
		}
	}

	// If there is no reason not to use the batch lookup iterator, use it
	return &batchLookupIterator{
		BPFMap: m,
	}
}
