package main

import (
	"fmt"
	"os"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

const mapSize = 10

func main() {
	testMap := &gobpfld.BPFGenericMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("xdp_stats_map"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize + 1,
			},
		},
	}
	var (
		key   uint32
		value uint64
	)

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

	fmt.Println("[iterator foreach pointers]")
	fmt.Println("------------------------")

	iter := testMap.Iterator()
	err = gobpfld.MapIterForEach(iter, &key, &value, func(_, _ interface{}) error {
		fmt.Printf("key: %d, value: %d\n", key, value)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "foreach ptr: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("\n[iterator foreach values]")
	fmt.Println("------------------------")

	iter = testMap.Iterator()
	err = gobpfld.MapIterForEach(iter, uint32(0), uint64(0), func(k, v interface{}) error {
		kp := k.(*uint32)
		vp := v.(*uint64)
		fmt.Printf("key: %d, value: %d\n", *kp, *vp)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "foreach value: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("\n[iterator init + next]")
	fmt.Println("------------------------")

	iter = testMap.Iterator()
	err = iter.Init(&key, &value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error iter init: %s\n", err.Error())
		os.Exit(1)
	}

	var updated bool
	for updated, err = iter.Next(); updated && err == nil; updated, err = iter.Next() {
		fmt.Printf("key: %v, value: %v\n", key, value)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error iter next: %s\n", err.Error())
		os.Exit(1)
	}

}
