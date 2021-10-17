package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

const mapSize = 10

func main() {
	normalMap := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("normal"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize + 1,
			},
		},
	}

	mmapMap := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("mmaped"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize + 1,

				// Make MMapable
				Flags: bpftypes.BPFMapFlagsMMapable,
			},
		},
	}

	err := normalMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading normal map: %s\n", err.Error())
		os.Exit(1)
	}

	err = mmapMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading mmap map: %s\n", err.Error())
		os.Exit(1)
	}

	for i := uint32(1); i <= mapSize; i++ {
		val := uint64(i * 10)
		err = normalMap.Set(i, &val, bpfsys.BPFMapElemAny)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting to normal map: %s\n", err.Error())
			os.Exit(1)
		}

		err = mmapMap.Set(i, &val, bpfsys.BPFMapElemAny)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting to normal map: %s\n", err.Error())
			os.Exit(1)
		}
	}

	fmt.Println("[Normal map]")
	fmt.Println("------------------------")

	start := time.Now()
	for i := uint32(0); i < 1000000; i++ {
		var val uint64
		err = normalMap.Get(i&mapSize, &val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while getting from normal map: %s\n", err.Error())
			os.Exit(1)
		}
	}
	dur := time.Since(start)
	fmt.Printf("1M took %v, %v per-op\n", dur, dur/1000000)

	start = time.Now()
	for i := uint32(0); i < 1000000; i++ {
		var val uint64
		err = mmapMap.Get(i&mapSize, &val)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while getting from normal map: %s\n", err.Error())
			os.Exit(1)
		}
	}

	dur = time.Since(start)
	fmt.Printf("1M took %v, %v per-op\n", dur, dur/1000000)

	fmt.Println("\n[Normal map iterator foreach pointers]")
	fmt.Println("------------------------")

	var (
		key   uint32
		value uint64
	)

	start = time.Now()
	iter := normalMap.Iterator()
	err = gobpfld.MapIterForEach(iter, &key, &value, func(_, _ interface{}) error {
		fmt.Printf("key: %d, value: %d\n", key, value)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "foreach ptr: %s\n", err.Error())
		os.Exit(1)
	}
	dur = time.Since(start)
	fmt.Printf("1 iter took %v\n", dur)

	fmt.Println("\n[MMapped map iterator foreach pointers]")
	fmt.Println("------------------------")

	start = time.Now()
	iter = mmapMap.Iterator()
	err = gobpfld.MapIterForEach(iter, &key, &value, func(_, _ interface{}) error {
		fmt.Printf("key: %d, value: %d\n", key, value)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "foreach ptr: %s\n", err.Error())
		os.Exit(1)
	}
	dur = time.Since(start)
	fmt.Printf("1 iter took %v\n", dur)
}
