package emulator

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

// Map represents an emulated eBPF map
type Map interface {
	Init() error

	GetName() string

	GetDef() gobpfld.BPFMapDef

	// Lookup looks up a value in the map for a given key and return a pointer to the value or NULL/0 if it can't find
	// it.
	Lookup(key RegisterValue) (RegisterValue, error)

	// Update sets or updates a map with value at the given key, it returns 0 on success or a negative value
	// on error.
	Update(key RegisterValue, value RegisterValue, flags bpfsys.BPFAttrMapElemFlags) (RegisterValue, error)

	// Delete deletes the value at the given key from the map
	Delete(key RegisterValue, flags bpfsys.BPFAttrMapElemFlags) error
}

// AbstractMapToVM converts an AbstractMap to an emulated version
func AbstractMapToVM(am gobpfld.AbstractMap) (Map, error) {
	switch am.Definition.Type {
	case bpftypes.BPF_MAP_TYPE_ARRAY:
		return &ArrayMap{Name: am.Name.String(), Def: am.Definition, InitialData: am.InitialData}, nil
	}

	return nil, fmt.Errorf("map type '%s' not yet implemented", am.Definition.Type)
}
