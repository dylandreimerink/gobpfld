//go:build bpftests
// +build bpftests

package integration

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

func TestIntegrationMapPinning(t *testing.T) {
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIObjPinGet) {
		t.Skip("skipping, current kernel version doesn't support pinning")
	}

	const mapSize = 100

	testMap := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("xdp_stats_map"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize,
			},
		},
	}
	testMap2 := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("xdp_stats_map2"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize,
			},
		},
	}

	pinPath2 := "abc/gei"

	err := testMap2.Load()
	if err != nil {
		panic(fmt.Errorf("error while loading map: %w", err))
	}

	// Pin map 2 to the FS
	err = testMap2.Pin(pinPath2)
	if err != nil {
		panic(fmt.Errorf("error while pinning map: %w", err))
	}

	// Unload it so we can unpin it later
	err = testMap2.Close()
	if err != nil {
		panic(fmt.Errorf("error while unloading map: %w", err))
	}

	// Load map 1
	err = testMap.Load()
	if err != nil {
		panic(fmt.Errorf("error while loading map: %w", err))
	}

	pinPath := "abc/def"

	// Pin to the same dir as map 2
	err = testMap.Pin(pinPath)
	if err != nil {
		panic(fmt.Errorf("error while pinning map: %w", err))
	}

	// Load map 1 so we can unpin it
	err = testMap.Close()
	if err != nil {
		panic(fmt.Errorf("error while unloading map: %w", err))
	}

	// Unpin and remove pinned file
	err = testMap.Unpin(pinPath, true)
	if err != nil {
		panic(fmt.Errorf("error while unpinning map: %w", err))
	}

	// Stat the dir to check that removing map 2 didn't remove the "abc" dir which still contains
	// the pinned map 2
	stat, err := os.Stat(fmt.Sprint(gobpfld.BPFSysPath, path.Dir(pinPath)))
	if err != nil {
		panic(fmt.Errorf("error while stating dir '%s': %w", path.Dir(pinPath), err))
	}
	if !stat.IsDir() {
		panic(fmt.Errorf("path is not a dir: %s\n", path.Dir(pinPath)))
	}

	// Increment map 1 to check that the unpinned map 1 is still accessible
	key := uint32(0)
	value := uint64(0)

	err = testMap.Get(key, &value)
	if err != nil {
		panic(fmt.Errorf("error while getting from map: %w", err))
	}

	value++

	err = testMap.Set(key, &value, bpfsys.BPFMapElemAny)
	if err != nil {
		panic(fmt.Errorf("error while setting to map: %w", err))
	}

	// Unpin + remove map 2 to cleanup
	err = testMap2.Unpin(pinPath2, true)
	if err != nil {
		panic(fmt.Errorf("error while unloading map: %w", err))
	}

	// Check that the dir of the pin path now has been removed after the last pinned map was unpinned
	_, err = os.Stat(fmt.Sprint(gobpfld.BPFSysPath, path.Dir(pinPath)))
	if err == nil {
		panic(fmt.Errorf("no error while stating pin path dir: %s\n", path.Dir(pinPath)))
	}
}
