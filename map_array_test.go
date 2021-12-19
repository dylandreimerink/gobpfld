// +build bpftests

package gobpfld

import (
	"fmt"
	"math/rand"
	"testing"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

const (
	sizeOfUint32 = uint32(unsafe.Sizeof(uint32(0)))
	sizeOfUint64 = uint32(unsafe.Sizeof(uint64(0)))
)

func testArraymap_SingleGetSet_happyPath(t *testing.T, arrayMap *ArrayMap, maxEntries int) {
	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Just a simple go slice used to verify BPF map behavior.
	verificationMap := make([]uint64, maxEntries)

	// In a loop, read random values from both maps and compare them, then update that key in both maps for later
	// iterations.
	for i := 0; i < 1000000; i++ {
		// Give us a random key that is sometimes(+5) outside of the map
		randKey := rand.Int31n(int32(maxEntries + 5))

		var a uint64
		err = arrayMap.Get(uint32(randKey), &a)
		// If randkey was outside of the map, we expect an error
		if int(randKey) >= maxEntries {
			if err == nil {
				t.Fatal("getting keys outside of the map didn't result in an error")
			}

			// Now lets see if Set also gives us an error, it should.
			err = arrayMap.Set(uint32(randKey), &a, bpfsys.BPFMapElemAny)
			if err == nil {
				t.Fatal("setting keys outside of the map didn't result in an error")
			}

			// Continue, since we don't have any result value to compare
			continue
		} else {
			// In all other cases we don't expect an error
			if err != nil {
				t.Fatal(err)
			}
		}

		v := verificationMap[randKey]

		// If the current verification value isn't equal to the actual value, the implementation is broken.
		if v != a {
			t.Fatal(fmt.Errorf("v=%d, a=%d, should be equal", v, a))
		}

		newVal := rand.Uint64()
		verificationMap[randKey] = newVal
		err = arrayMap.Set(uint32(randKey), &newVal, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Tests that getting and setting of single keys work for a normal array map
func TestArrayMap_SingleGetSet_HappyPath(t *testing.T) {
	const maxEntries = 1000
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	testArraymap_SingleGetSet_happyPath(t, &arrayMap, maxEntries)
}

// Tests that getting and setting of single keys work for a mmaped array map
func TestArrayMapMMAP_SingleGetSet_HappyPath(t *testing.T) {
	// We can only perform this test if the kernel we are running on supports it
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapMMap) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 1000
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
				Flags:      bpftypes.BPFMapFlagsMMapable,
			},
		},
	}

	testArraymap_SingleGetSet_happyPath(t, &arrayMap, maxEntries)
}

func testArraymap_BatchGetSet_happyPath(t *testing.T, arrayMap *ArrayMap, maxEntries int) {
	// We can only perform this test if the kernel we are running on supports it
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBatchOps) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Just a simple go slice used to verify BPF map behavior.
	verificationMap := make([]uint64, maxEntries)

	// In a loop, read random values from both maps and compare them, then update that key in both maps for later
	// iterations.
	for i := 0; i < 10000; i++ {
		batchSize := rand.Intn(maxEntries + 2)
		keys := make([]uint32, batchSize)
		values := make([]uint64, batchSize)

		count, partial, err := arrayMap.GetBatch(keys, &values)
		if err != nil {
			t.Fatal(err)
		}
		keys = keys[:count]
		values = values[:count]

		// If the batch was bigger than the map size, we expect to only get a partial return
		if batchSize > maxEntries {
			if !partial {
				t.Fatal("GetBatch returned partial=false when all values were read")
			}
		} else {
			if partial {
				t.Fatal("GetBatch returned partial=true when not all values were read")
			}
			if count != batchSize {
				t.Fatalf("GetBatch, count=%d, batchSize=%d, should be equal when err = nil", count, batchSize)
			}
		}

		for j := 0; j < count; j++ {
			v := verificationMap[keys[j]]
			a := values[j]

			// If the current verification value isn't equal to the actual value, the implementation is broken.
			if v != a {
				t.Fatal(fmt.Errorf("v=%d, a=%d, should be equal", v, a))
			}

			newValue := rand.Uint64()
			verificationMap[keys[j]] = newValue
			values[j] = newValue
		}

		count, err = arrayMap.SetBatch(keys, &values, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
		if count != len(keys) {
			t.Fatal(fmt.Errorf("SetBatch, count=%d, len(keys)=%d, should be equal when err = nil", count, len(keys)))
		}
	}

	// Cleanup the map, in case we run multiple tests in a same run
	err = arrayMap.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Tests that getting and setting of bulk keys work for a normal array map
func TestArrayMap_BulkGetSet_HappyPath(t *testing.T) {
	const maxEntries = 1000
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	testArraymap_BatchGetSet_happyPath(t, &arrayMap, maxEntries)
}

// Tests that getting and setting of bulk keys work for a normal array map
func TestArrayMapMMap_BulkGetSet_HappyPath(t *testing.T) {
	const maxEntries = 1000
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
				Flags:      bpftypes.BPFMapFlagsMMapable,
			},
		},
	}

	testArraymap_BatchGetSet_happyPath(t, &arrayMap, maxEntries)
}

func TestArrayMapMMap_BulkGetSet_Edgecases(t *testing.T) {
	// We can only perform this test if the kernel we are running on supports it
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapMMap) {
		t.Skip("Skip because the feature is not supported by current kernel version")
	}

	const maxEntries = 1000
	arrayMap := ArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
				Flags:      bpftypes.BPFMapFlagsMMapable,
			},
		},
	}

	// map is still unloaded

	var v uint64
	err := arrayMap.Get(0, &v)
	if err == nil {
		t.Fatal("calling Get on an unloaded map didn't give an error")
	}

	err = arrayMap.Set(0, &v, bpfsys.BPFMapElemAny)
	if err == nil {
		t.Fatal("calling Set on an unloaded map didn't give an error")
	}

	_, _, err = arrayMap.GetBatch(nil, &v)
	if err == nil {
		t.Fatal("calling GetBatch on an unloaded map didn't give an error")
	}

	_, err = arrayMap.SetBatch(nil, &v, bpfsys.BPFMapElemAny)
	if err == nil {
		t.Fatal("calling SetBatch on an unloaded map didn't give an error")
	}

	err = arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}

	keys := []uint32{1005}
	values := []uint64{123456}
	_, err = arrayMap.SetBatch(keys, &values, bpfsys.BPFMapElemAny)
	if err == nil {
		t.Fatal("calling SetBatch with out of bound keys should give an error")
	}

	// Cleanup the map, in case we run multiple tests in a same run
	err = arrayMap.Close()
	if err != nil {
		t.Fatal(err)
	}
}
