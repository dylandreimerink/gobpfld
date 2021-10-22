package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*ArrayOfMapsMap)(nil)

// ArrayOfMapsMap is a map which has a integer key from 0 to MaxEntries. The value type must be any loaded BPF map
type ArrayOfMapsMap struct {
	AbstractMap
}

func (m *ArrayOfMapsMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_ARRAY_OF_MAPS when using an ArrayOfMapsMap")
	}

	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapArrayOfMaps) {
		return fmt.Errorf("Array of maps map type is not supported by the current kernel version")
	}

	return m.load()
}

// Unload closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *ArrayOfMapsMap) Unload() error {
	return m.unload()
}

func (m *ArrayOfMapsMap) Get(key uint32) (BPFMap, error) {
	var fd bpfsys.BPFfd
	err := m.get(&key, &fd)
	if err != nil {
		return nil, fmt.Errorf("map get: %w", err)
	}

	return MapFromFD(fd)
}

func (m *ArrayOfMapsMap) Set(key uint32, value BPFMap, flags bpfsys.BPFAttrMapElemFlags) error {
	fd := value.GetFD()
	return m.set(&key, &fd, flags)
}

func (m *ArrayOfMapsMap) Iterator() MapIterator {
	return &singleMapLookupIterator{
		BPFMap: m,
	}
}
