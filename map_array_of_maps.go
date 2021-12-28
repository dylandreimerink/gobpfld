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

	// InnerMapDef is the definition of the inner map
	// TODO: Once BTF is implemented we can infer this map type from the BTF debug symbols
	InnerMapDef BPFMapDef
	// innerMapDef is a copy of the publicly available map def, so it can't be change while the map is loaded
	innerMapDef BPFMapDef
}

func (m *ArrayOfMapsMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_ARRAY_OF_MAPS when using an ArrayOfMapsMap")
	}

	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapArrayOfMaps) {
		return fmt.Errorf("Array of maps map type is not supported by the current kernel version")
	}

	err := m.loadArrayOfMaps()
	if err != nil {
		return err
	}

	err = mapRegister.add(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return nil
}

// loadPseudoInnerMap will load a map into the kernel with m.InnerMapDef as definition and returns the FD for this map.
func (m *ArrayOfMapsMap) loadPseudoInnerMap() (*AbstractMap, error) {
	if kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapDynamicInnerMap) {
		// Set the inner map flag
		m.InnerMapDef.Flags |= bpftypes.BPFMapFlagsInnerMap
	}

	innerMap := &AbstractMap{
		Name:       MustNewObjName("pseudoinnermap"),
		Definition: m.InnerMapDef,
	}

	return innerMap, innerMap.load(nil)
}

// loadArrayOfMaps will first create a pseudo map, the FD of which we need to pass when loading the outermap to provide
// type information. The verifier uses this type information to verify how values from the inner map are used.
func (m *ArrayOfMapsMap) loadArrayOfMaps() error {
	err := m.Definition.Validate()
	if err != nil {
		return err
	}

	innerMap, err := m.loadPseudoInnerMap()
	if err != nil {
		return fmt.Errorf("load pseudo inner map: %w", err)
	}
	// Copy the def so it can't be changed after loading
	m.innerMapDef = m.InnerMapDef

	err = m.load(func(attr *bpfsys.BPFAttrMapCreate) {
		attr.InnerMapFD = innerMap.fd
	})
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}

	// After the outer map has been loaded, the inner map type info is copied so we can unload the pseudo inner map.
	err = innerMap.close()
	if err != nil {
		return fmt.Errorf("inner pseudomap unload: %w", err)
	}

	return nil
}

// Close closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *ArrayOfMapsMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}

func (m *ArrayOfMapsMap) Get(key uint32) (BPFMap, error) {
	var id uint32
	err := m.get(&key, &id)
	if err != nil {
		return nil, fmt.Errorf("map get: %w", err)
	}

	return MapFromID(id)
}

func (m *ArrayOfMapsMap) Set(key uint32, value BPFMap, flags bpfsys.BPFAttrMapElemFlags) error {
	if !value.IsLoaded() {
		return fmt.Errorf("only loaded maps can be set as inner map")
	}

	def := value.GetDefinition()
	if def.Flags&bpftypes.BPFMapFlagsInnerMap != 0 {
		// If the inner map flag is set, max entries can be ignored when comparing inner maps.
		// Since the Equal function doesn't take this edge case
		// into account we will just make the MaxEntries of def equal.
		// This doesn't update the actual value of the map since we are working with a copy of the definition
		def.MaxEntries = m.innerMapDef.MaxEntries
	}

	if !def.Equal(m.innerMapDef) {
		return fmt.Errorf("map definition of the 'value' doesn't match the inner map definition")
	}

	fd := value.GetFD()
	return m.set(&key, &fd, flags)
}

func (m *ArrayOfMapsMap) Iterator() MapIterator {
	return &singleMapLookupIterator{
		BPFMap: m,
	}
}
