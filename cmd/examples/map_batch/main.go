package main

import (
	"fmt"
	"os"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

const mapSize = 5

func main() {
	testMap := &gobpfld.BPFGenericMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("xdp_stats_map"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_HASH,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize,
			},
		},
	}

	err := testMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading map: %s\n", err.Error())
		os.Exit(1)
	}

	for i := uint32(1); i <= mapSize; i++ {
		val := uint64(i * 10)
		err = testMap.Set(&i, &val, bpfsys.BPFMapElemAny)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting to map: %s\n", err.Error())
			os.Exit(1)
		}
	}

	fmt.Println("[loop and get]")
	fmt.Println("------------------------")

	for i := uint32(1); i <= mapSize; i++ {
		var val uint64
		err = testMap.Get(&i, &val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting to map: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("%d = %d\n", i, val)
	}

	fmt.Println("\n[get batch]")
	fmt.Println("------------------------")

	keys := make([]uint32, mapSize)
	values := make([]uint64, mapSize)
	count, _, err := testMap.GetBatch(&keys, &values, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Got %d elements\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("%d = %d\n", keys[i], values[i])
	}

	fmt.Println("\n[delete batch]")
	fmt.Println("------------------------")

	count, err = testMap.DeleteBatch(&keys, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Deleted %d elements\n", count)

	count, _, err = testMap.GetBatch(&keys, &values, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Got %d elements\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("%d = %d\n", keys[i], values[i])
	}

	fmt.Println("\n[add batch]")
	fmt.Println("------------------------")

	count, err = testMap.SetBatch(&keys, &values, bpfsys.BPFMapElemAny, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Set %d elements\n", count)

	count, _, err = testMap.GetBatch(&keys, &values, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Got %d elements\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("%d = %d\n", keys[i], values[i])
	}

	fmt.Println("\n[update batch]")
	fmt.Println("------------------------")

	for i := 0; i < mapSize; i++ {
		values[i] = uint64(values[i] + 100)
	}

	count, err = testMap.SetBatch(&keys, &values, bpfsys.BPFMapElemExists, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Updated %d elements\n", count)

	count, _, err = testMap.GetBatch(&keys, &values, mapSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while getting batch: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Got %d elements\n", count)
	for i := 0; i < count; i++ {
		fmt.Printf("%d = %d\n", keys[i], values[i])
	}
}
