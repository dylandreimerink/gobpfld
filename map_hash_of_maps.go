package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*HashOfMapsMap)(nil)

// HashOfMapsMap is a map with as value another map, the value type must be any loaded BPF map. The key type can be
// anything, the keys are hashed and thus do not need to be contiguous.
type HashOfMapsMap struct {
	AbstractMap
}

func (m *HashOfMapsMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_HASH_OF_MAPS when using an HashOfMapsMap")
	}

	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapHashOfMaps) {
		return fmt.Errorf("Hash of maps map type is not supported by the current kernel version")
	}

	return m.load()
}

// Unload closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *HashOfMapsMap) Unload() error {
	return m.unload()
}

func (m *HashOfMapsMap) Get(key interface{}) (BPFMap, error) {
	var fd bpfsys.BPFfd
	err := m.get(&key, &fd)
	if err != nil {
		return nil, fmt.Errorf("map get: %w", err)
	}

	return MapFromFD(fd)
}

func (m *HashOfMapsMap) Set(key interface{}, value BPFMap, flags bpfsys.BPFAttrMapElemFlags) error {
	fd := value.GetFD()
	return m.set(&key, &fd, flags)
}

func (m *HashOfMapsMap) Iterator() MapIterator {
	return &singleMapLookupIterator{
		BPFMap: m,
	}
}
