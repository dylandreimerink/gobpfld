package main

import (
	"fmt"
	"os"
	"path"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

// This example command demonstrates and tests pinning and unpinning of maps

const mapSize = 100

func main() {
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
		fmt.Fprintf(os.Stderr, "error while loading map: %s\n", err.Error())
		os.Exit(1)
	}

	// Pin map 2 to the FS
	err = testMap2.Pin(pinPath2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while pinning map: %s\n", err.Error())
		os.Exit(1)
	}

	// Unload it so we can unpin it later
	err = testMap2.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while unloading map: %s\n", err.Error())
		os.Exit(1)
	}

	// Load map 1
	err = testMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading map: %s\n", err.Error())
		os.Exit(1)
	}

	pinPath := "abc/def"

	// Pin to the same dir as map 2
	err = testMap.Pin(pinPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while pinning map: %s\n", err.Error())
		os.Exit(1)
	}

	// Load map 1 so we can unpin it
	err = testMap.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while unloading map: %s\n", err.Error())
		os.Exit(1)
	}

	// Unpin and remove pinned file
	err = testMap.Unpin(pinPath, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while unpinning map: %s\n", err.Error())
		os.Exit(1)
	}

	// Stat the dir to check that removing map 2 didn't remove the "abc" dir which still contains
	// the pinned map 2
	stat, err := os.Stat(fmt.Sprint(gobpfld.BPFSysPath, path.Dir(pinPath)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while stating dir '%s': %s\n", path.Dir(pinPath), err.Error())
		os.Exit(1)
	}
	if !stat.IsDir() {
		fmt.Fprintf(os.Stderr, "path is not a dir: %s\n", path.Dir(pinPath))
		os.Exit(1)
	}

	// Increment map 1 to check that the unpinned map 1 is still accessible
	key := uint32(0)
	value := uint64(0)

	err = testMap.Get(key, &value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting from map: %s\n", err.Error())
		os.Exit(1)
	}

	value++

	err = testMap.Set(key, &value, bpfsys.BPFMapElemAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while setting to map: %s\n", err.Error())
		os.Exit(1)
	}

	// Unpin + remove map 2 to cleanup
	err = testMap2.Unpin(pinPath2, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while unloading map: %s\n", err.Error())
		os.Exit(1)
	}

	// Check that the dir of the pin path now has been removed after the last pinned map was unpinned
	_, err = os.Stat(fmt.Sprint(gobpfld.BPFSysPath, path.Dir(pinPath)))
	if err == nil {
		fmt.Fprintf(os.Stderr, "no error while stating pin path dir: %s\n", path.Dir(pinPath))
		os.Exit(1)
	}
}
