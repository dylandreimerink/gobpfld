package emulator

import (
	"errors"
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
	GetType() gobpfld.BTFMap

	// Keys returns all keys contained in the map
	Keys() []RegisterValue

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
	case bpftypes.BPF_MAP_TYPE_HASH, bpftypes.BPF_MAP_TYPE_PERCPU_HASH:
		// NOTE since the emulator currently only support single threading, a per-cpu map is effectively the same
		// as a normal map. As soon as we want to support parallel execution, we should add an actual separate
		// type
		return &HashMap{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_ARRAY, bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:
		// NOTE since the emulator currently only support single threading, a per-cpu map is effectively the same
		// as a normal map. As soon as we want to support parallel execution, we should add an actual separate
		// type
		return &ArrayMap{
			Name:        am.Name.String(),
			Def:         am.Definition,
			InitialData: am.InitialData,
			BTFType:     am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_PROG_ARRAY:
		// In linux this needs to be a special map type because it holds addresses to programs, but in the emulator
		// we can just insert the program indexes, so it is effectively a normal array map with an int32 value
		return &ArrayMap{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		return &PerfEventArray{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_LRU_HASH, bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH:
		// NOTE since the emulator currently only support single threading, a per-cpu map is effectively the same
		// as a normal map. As soon as we want to support parallel execution, we should add an actual separate
		// type
		return &HashMapLRU{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:
		// In linux this needs to be a special may type because it holds addresses to maps, but in the emulator
		// we can just insert the map indexes, so it is effectively a normal array map with a int32 value
		return &ArrayMap{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	case bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS:
		// In linux this needs to be a special may type because it holds addresses to maps, but in the emulator
		// we can just insert the map indexes, so it is effectively a normal hash map with a int32 value
		return &HashMap{
			Name:    am.Name.String(),
			Def:     am.Definition,
			BTFType: am.BTFMapType,
		}, nil
	}

	return nil, fmt.Errorf("map type '%s' not yet implemented", am.Definition.Type)
}

var (
	errMapNotImplemented = errors.New("feature is not implemented on this map type")
	errMapKeyNoPtr       = errors.New("key is not a pointer")
	errMapValNoPtr       = errors.New("value is not a pointer")
	errMapOutOfMemory    = errors.New("map is full or access outside of bounds")
)
