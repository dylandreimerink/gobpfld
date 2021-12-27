//go:build bpftests
// +build bpftests

package gobpfld

import (
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"testing"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

func testPerCPUArraymap_SingleGetSet_happyPath(t *testing.T, arrayMap *PerCPUArrayMap, maxEntries int) {
	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}

	cpuCount := runtime.NumCPU()

	// Just a simple go slice used to verify BPF map behavior.
	verificationMap := make([]uint64, maxEntries*cpuCount)

	// Test with less iterations in short mode
	iter := 100000
	if testing.Short() {
		iter = 1000
	}

	// In a loop, read random values from both maps and compare them, then update that key in both maps for later
	// iterations.
	for i := 0; i < iter; i++ {
		// Give us a random key that is sometimes(+5) outside of the map
		randKey := rand.Int31n(int32(maxEntries + 5))

		a := make([]uint64, cpuCount)
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

		v := verificationMap[randKey*int32(cpuCount) : (randKey+1)*int32(cpuCount)]

		// If the current verification value isn't equal to the actual value, the implementation is broken.
		if !reflect.DeepEqual(v, a) {
			t.Fatal(fmt.Errorf("v=%v, a=%v, should be equal", v, a))
		}

		newVal := make([]uint64, cpuCount)
		for j := range newVal {
			newVal[j] = rand.Uint64()
		}
		copy(verificationMap[randKey*int32(cpuCount):(randKey+1)*int32(cpuCount)], newVal)

		err = arrayMap.Set(uint32(randKey), &newVal, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Cleanup the map, in case we run multiple tests in a same run
	err = arrayMap.Close()
	if err != nil {
		t.Fatal(err)
	}
}

// Tests that getting and setting of single keys work for a normal array map
func TestPerCPUArrayMap_SingleGetSet_HappyPath(t *testing.T) {
	const maxEntries = 1000
	arrayMap := PerCPUArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	testPerCPUArraymap_SingleGetSet_happyPath(t, &arrayMap, maxEntries)
}

func testPerCPUArrayMap_BatchGetSet_happyPath(t *testing.T, arrayMap *PerCPUArrayMap, maxEntries int) {
	err := arrayMap.Load()
	if err != nil {
		t.Fatal(err)
	}

	cpuCount := runtime.NumCPU()

	// Just a simple go slice used to verify BPF map behavior.
	verificationMap := make([]uint64, maxEntries*cpuCount)

	// Test with less iterations in short mode
	iter := 10000
	if testing.Short() {
		iter = 1000
	}

	// In a loop, read random values from both maps and compare them, then update that key in both maps for later
	// iterations.
	for i := 0; i < iter; i++ {
		batchSize := rand.Intn(maxEntries + 2)
		keys := make([]uint32, batchSize)
		values := make([]uint64, batchSize*cpuCount)

		count, partial, err := arrayMap.GetBatch(keys, &values)
		if err != nil {
			t.Fatal(err)
		}
		keys = keys[:count]
		values = values[:count*cpuCount]

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
func TestPerCPUArrayMap_BulkGetSet_HappyPath(t *testing.T) {
	// We can only perform this test if the kernel we are running on supports it
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapPerCPUArrayBatchOps) {
		t.Skip("Skip because the feature is not supported by kernel")
	}

	const maxEntries = 1000
	arrayMap := PerCPUArrayMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY,
				KeySize:    sizeOfUint32,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	testPerCPUArrayMap_BatchGetSet_happyPath(t, &arrayMap, maxEntries)
}
