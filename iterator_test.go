package gobpfld

import (
	"math/rand"
	"testing"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var sizeOfmapIterTestKey = uint32(unsafe.Sizeof(mapIterTestKey{}))

type mapIterTestKey struct {
	A uint32
	B uint64
}

var sizeOfmapIterTestValue = uint32(unsafe.Sizeof(mapIterTestValue{}))

type mapIterTestValue struct {
	C uint64
	D byte
}

func testHashMapIteratorHappyPath(t *testing.T, hashMap *HashMap, iter MapIterator, maxEntries int) {
	err := hashMap.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer hashMap.Close()

	// Just a simple go map used to verify BPF map behavior.
	verificationMap := make(map[mapIterTestKey]mapIterTestValue, maxEntries)

	// Fill the whole map verification map
	for len(verificationMap) < maxEntries {
		key := mapIterTestKey{
			A: rand.Uint32(),
			B: rand.Uint64(),
		}

		_, ok := verificationMap[key]
		if !ok {
			verificationMap[key] = mapIterTestValue{
				C: rand.Uint64(),
				D: byte(rand.Intn(255)),
			}
		}
	}

	// Copy verification map to BPF map, so contents are identical
	for k, v := range verificationMap {
		hashMap.Set(&k, &v, bpfsys.BPFMapElemAny)
	}

	var k mapIterTestKey
	var v mapIterTestValue
	err = iter.Init(&k, &v)
	if err != nil {
		t.Fatal(err)
	}

	for {
		updated, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !updated {
			break
		}

		verifyValue, ok := verificationMap[k]
		if !ok {
			t.Fatalf("key %v doesn't exist in verification map", k)
		}
		if verifyValue.C != v.C || verifyValue.D != v.D {
			t.Fatalf("value %v from BPF map doesn't match value in verification map %v", k, verifyValue)
		}

		// Delete key from verification map, so we know we have read it exactly once
		delete(verificationMap, k)
	}

	if len(verificationMap) > 0 {
		t.Fatalf("not all values in verification map have been read, %d still left", len(verificationMap))
	}
}

func TestSingleLookupIteratorHappyPath(t *testing.T) {
	const maxEntries = 128
	hashMap := HashMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_HASH,
				KeySize:    sizeOfmapIterTestKey,
				ValueSize:  sizeOfmapIterTestValue,
				MaxEntries: maxEntries,
			},
		},
	}
	iter := &singleLookupIterator{
		BPFMap: &hashMap,
	}

	testHashMapIteratorHappyPath(t, &hashMap, iter, maxEntries)
}

func TestBatchLookupIteratorHappyPath(t *testing.T) {
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBatchOps) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 128
	hashMap := HashMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_HASH,
				KeySize:    sizeOfmapIterTestKey,
				ValueSize:  sizeOfmapIterTestValue,
				MaxEntries: maxEntries,
			},
		},
	}
	iter := &batchLookupIterator{
		BPFMap: &hashMap,
	}

	testHashMapIteratorHappyPath(t, &hashMap, iter, maxEntries)
}

func TestIterForEachHappyPath(t *testing.T) {
	const maxEntries = 128
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // Array maps always have 32bit keys (4 bytes)
				ValueSize:  sizeOfmapIterTestValue,
				MaxEntries: maxEntries,
			},
		},
	}

	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer arrayMap.Close()

	// Just a simple go map used to verify BPF map behavior.
	verificationMap := make([]mapIterTestValue, maxEntries)

	// Fill the whole map verification map
	for i := 0; i < maxEntries; i++ {
		verificationMap[i] = mapIterTestValue{
			C: rand.Uint64(),
			D: byte(rand.Intn(255)),
		}
	}

	// Copy verification map to BPF map, so contents are identical
	for k, v := range verificationMap {
		err := arrayMap.Set(uint32(k), &v, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}

	readMap := make([]bool, len(verificationMap))

	var k uint32
	var v mapIterTestValue
	MapIterForEach(arrayMap.Iterator(), &k, &v, func(key, value interface{}) error {
		if int(k) >= len(verificationMap) {
			t.Fatalf("key %v doesn't exist in verification map", k)
		}
		verifyValue := verificationMap[k]
		if verifyValue.C != v.C || verifyValue.D != v.D {
			t.Fatalf("value at %d %v from BPF map doesn't match value in verification map %v", k, v, verifyValue)
		}
		if readMap[k] {
			t.Fatalf("double read of same key %d", k)
		}

		readMap[k] = true

		return nil
	})

	for k, v := range readMap {
		if !v {
			t.Fatalf("key %d was not read", k)
		}
	}
}

func testArrayMapIteratorHappyPath(t *testing.T, arrayMap *ArrayMap, iter MapIterator, maxEntries int) {
	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer arrayMap.Close()

	// Just a simple go map used to verify BPF map behavior.
	verificationMap := make([]mapIterTestValue, maxEntries)

	// Fill the whole map verification map
	for i := 0; i < maxEntries; i++ {
		verificationMap[i] = mapIterTestValue{
			C: rand.Uint64(),
			D: byte(rand.Intn(255)),
		}
	}

	// Copy verification map to BPF map, so contents are identical
	for k, v := range verificationMap {
		arrayMap.Set(uint32(k), &v, bpfsys.BPFMapElemAny)
	}

	var k uint32
	var v mapIterTestValue
	err = iter.Init(&k, &v)
	if err != nil {
		t.Fatal(err)
	}

	readMap := make([]bool, len(verificationMap))

	for {
		updated, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !updated {
			break
		}

		if int(k) >= len(verificationMap) {
			t.Fatalf("key %v doesn't exist in verification map", k)
		}
		verifyValue := verificationMap[k]
		if verifyValue.C != v.C || verifyValue.D != v.D {
			t.Fatalf("value at %d %v from BPF map doesn't match value in verification map %v", k, v, verifyValue)
		}
		if readMap[k] {
			t.Fatalf("double read of same key %d", k)
		}

		readMap[k] = true
	}

	for k, v := range readMap {
		if !v {
			t.Fatalf("key %d was not read", k)
		}
	}
}

func TestMMappedIteratorHappyPath(t *testing.T) {
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapMMap) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 128
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // Array maps always have 32bit keys (4 bytes)
				ValueSize:  sizeOfmapIterTestValue,
				MaxEntries: maxEntries,
				Flags:      bpftypes.BPFMapFlagsMMapable, // Must be loaded as mmappable
			},
		},
	}
	iter := &mmappedIterator{
		am: &arrayMap,
	}

	testArrayMapIteratorHappyPath(t, &arrayMap, iter, maxEntries)
}

func TestSingleMapIteratorHappyPath(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapArrayOfMaps) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 8
	arrayOfMaps := &ArrayOfMapsMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS,
				KeySize:    4, // Array maps always have 32bit keys (4 bytes)
				ValueSize:  4, // FD's is always 32bit (4 bytes)
				MaxEntries: maxEntries,
			},
		},
	}
	iter := &singleMapLookupIterator{
		BPFMap: arrayOfMaps,
	}

	// Just a simple go map used to verify BPF map behavior.
	verificationMap := make([]BPFMap, maxEntries)

	innerDef := BPFMapDef{
		Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 5,
	}

	// In some kernels <5.10 call inner maps must be the same size
	if kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapDynamicInnerMap) {
		innerDef.Flags |= bpftypes.BPFMapFlagsInnerMap
	}

	// Fill the whole map verification map
	for i := 0; i < maxEntries; i++ {
		verificationMap[i] = &ArrayMap{
			AbstractMap: AbstractMap{
				Name:       MustNewObjName("inner"),
				Definition: innerDef,
			},
		}
	}

	// Must set the inner map def before loading
	arrayOfMaps.InnerMapDef = innerDef

	err := arrayOfMaps.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer arrayOfMaps.Close()

	// Copy verification map to BPF map, so contents are identical
	for k, v := range verificationMap {
		// Must load every inner map before it can be set in a map-in-map
		err = v.Load()
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()

		err = arrayOfMaps.Set(uint32(k), v, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}

	var k uint32
	var v BPFMap
	err = iter.Init(&k, &v)
	if err != nil {
		t.Fatal(err)
	}

	readMap := make([]bool, len(verificationMap))

	for {
		updated, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !updated {
			break
		}

		if int(k) >= len(verificationMap) {
			t.Fatalf("key %v doesn't exist in verification map", k)
		}
		verifyValue := verificationMap[k]
		if verifyValue != v {
			t.Fatalf("value at %d %v from BPF map doesn't match value in verification map %v", k, v, verifyValue)
		}
		if readMap[k] {
			t.Fatalf("double read of same key %d", k)
		}

		readMap[k] = true
	}

	for k, v := range readMap {
		if !v {
			t.Fatalf("key %d was not read", k)
		}
	}
}

func TestSingleMapIteratorHashOfMapHappyPath(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapHashOfMaps) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 8
	hashOfMaps := &HashOfMapsMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS,
				KeySize:    4, // Array maps always have 32bit keys (4 bytes)
				ValueSize:  4, // FD's is always 32bit (4 bytes)
				MaxEntries: maxEntries,
			},
		},
	}
	iter := &singleMapLookupIterator{
		BPFMap: hashOfMaps,
	}

	// Just a simple go map used to verify BPF map behavior.
	verificationMap := make([]BPFMap, maxEntries)

	innerDef := BPFMapDef{
		Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 5,
	}

	// In some kernels <5.10 call inner maps must be the same size
	if kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapDynamicInnerMap) {
		innerDef.Flags |= bpftypes.BPFMapFlagsInnerMap
	}

	// Fill the whole map verification map
	for i := 0; i < maxEntries; i++ {
		verificationMap[i] = &ArrayMap{
			AbstractMap: AbstractMap{
				Name:       MustNewObjName("inner"),
				Definition: innerDef,
			},
		}
	}

	// Must set the inner map def before loading
	hashOfMaps.InnerMapDef = innerDef

	err := hashOfMaps.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer hashOfMaps.Close()

	// Copy verification map to BPF map, so contents are identical
	for k, v := range verificationMap {
		// Must load every inner map before it can be set in a map-in-map
		err = v.Load()
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()

		kCopy := uint32(k)
		err = hashOfMaps.Set(&kCopy, v, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}

	var k uint32
	var v BPFMap
	err = iter.Init(&k, &v)
	if err != nil {
		t.Fatal(err)
	}

	readMap := make([]bool, len(verificationMap))

	for {
		updated, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !updated {
			break
		}

		if int(k) >= len(verificationMap) {
			t.Fatalf("key %v doesn't exist in verification map", k)
		}
		verifyValue := verificationMap[k]
		if verifyValue != v {
			t.Fatalf("value at %d %v from BPF map doesn't match value in verification map %v", k, v, verifyValue)
		}
		if readMap[k] {
			t.Fatalf("double read of same key %d", k)
		}

		readMap[k] = true
	}

	for k, v := range readMap {
		if !v {
			t.Fatalf("key %d was not read", k)
		}
	}
}
