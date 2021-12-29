//go:build bpftests
// +build bpftests

package gobpfld

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

// TestLPMTrieMapHappyPath executes property based happy path testing, comparing the LPM map to a golang map, assuming the go map is always
// correct.
func TestLPMTrieMapHappyPath(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrie) {
		t.Skip("LPM tree not supported by current kernel version")
	}

	const maxEntries = 128

	m := &LPMTrieMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("lpmtest"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_LPM_TRIE,
				KeySize:    uint32(unsafe.Sizeof(LPMTrieIPv4Key{})),
				ValueSize:  8,
				MaxEntries: maxEntries + 1,
				Flags:      bpftypes.BPFMapFlagsNoPreAlloc,
			},
		},
	}

	err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	verificationMap := make(map[LPMTrieIPv4Key]uint64)

	randKey := func() *LPMTrieIPv4Key {
		_, cidr, err := net.ParseCIDR(fmt.Sprintf(
			"%d.%d.%d.%d/%d",
			rand.Intn(255),
			rand.Intn(255),
			rand.Intn(255),
			rand.Intn(255),
			rand.Intn(32),
		))
		if err != nil {
			t.Fatal(err)
		}

		// If the key already exists, generate another one
		return LPMKeyFromNetwork(*cidr).(*LPMTrieIPv4Key)
	}

	// Fill the verification map
	for i := 0; i < maxEntries; i++ {
		key := randKey()
		if _, ok := verificationMap[*key]; ok {
			i--
			continue
		}

		verificationMap[*key] = rand.Uint64()
	}

	// Transfer contents to BPF map
	for k, v := range verificationMap {
		// Copy the key, we can't pass a pointer to a temp variable
		kCopy := k
		vCopy := v
		err = m.Set(&kCopy, &vCopy, bpfsys.BPFMapElemAny)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Perform less permutations when the -short flag is passed
	limit := 1000
	if testing.Short() {
		limit = 100
	}

	// Fail if the maps don't match
	verify := func() {
		read := make(map[LPMTrieIPv4Key]struct{}, len(verificationMap))
		for k := range verificationMap {
			read[k] = struct{}{}
		}

		var (
			k LPMTrieIPv4Key
			v uint64
		)
		var iter MapIterator = &singleLookupIterator{BPFMap: m}
		if kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) && rand.Int()%2 == 0 {
			iter = &batchLookupIterator{BPFMap: m}
		}

		iter.Init(&k, &v)
		for {
			updated, err := iter.Next()
			if !updated {
				break
			}
			if err != nil {
				t.Fatal(err)
			}

			verifyValue, ok := verificationMap[k]
			if !ok {
				t.Fatal("key in map doesn't exist in verification map")
			}
			if verifyValue != v {
				t.Fatal("value doesn't match")
			}
			delete(read, k)
		}
		if err != nil {
			t.Fatal(err)
		}

		if len(read) > 0 {
			t.Fatalf("no all keys were read (%d/%d)", len(read), len(verificationMap))
		}
	}

	// Verify initial state
	verify()

	// Return a random key from the verification map
	randValKey := func() LPMTrieIPv4Key {
		kIndex := rand.Intn(len(verificationMap) - 1)
		ii := 0
		for k := range verificationMap {
			if ii == kIndex {
				return k
			}
			ii++
		}

		t.Fatal("should not be possible")
		return LPMTrieIPv4Key{}
	}

	// Update, delete, and add single keys and values
	for i := 0; i < limit; i++ {
		switch i % 3 {
		case 0:
			// Update
			newVal := rand.Uint64()
			k := randValKey()

			verificationMap[k] = newVal
			err := m.Set(&k, &newVal, bpfsys.BPFMapElemExists)
			if err != nil {
				t.Fatal(err)
			}

		case 1:
			// Delete
			k := randValKey()

			delete(verificationMap, k)
			err := m.Delete(&k)
			if err != nil {
				t.Fatal(err)
			}

		case 2:
			// Add
			newVal := rand.Uint64()
			k := randKey()

			verificationMap[*k] = newVal
			err := m.Set(k, &newVal, bpfsys.BPFMapElemNoExists)
			if err != nil {
				t.Fatal(err)
			}
		}

		verify()
	}

	// Can't execute the rest of the test if the current kernel doesn't support bulk ops
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapLPMTrieBatchOps) {
		return
	}

	// Update, delete, and add 10 keys and values at a time
	const batchSize = 10
	for i := 0; i < limit; i++ {
		keys := make([]LPMTrieIPv4Key, batchSize)
		values := make([]uint64, batchSize)

		switch i % 3 {
		case 0:
			// Update

			// Get random set of existing keys
			for j := 0; j < batchSize; j++ {
				randKey := randValKey()
				exists := false
				for _, v := range keys {
					if v == randKey {
						exists = true
					}
				}
				if exists {
					j--
					continue
				}
				keys[j] = randKey
			}

			for j := 0; j < batchSize; j++ {
				// Gen new value
				values[j] = rand.Uint64()

				// Update value in verification map
				verificationMap[keys[j]] = values[j]
			}

			_, err := m.SetBatch(&keys, &values, bpfsys.BPFMapElemExists, batchSize)
			if err != nil {
				t.Fatal(err)
			}

		case 1:
			// Delete

			// Get random set of existing keys
			for j := 0; j < batchSize; j++ {
				randKey := randValKey()
				exists := false
				for _, v := range keys {
					if v == randKey {
						exists = true
					}
				}
				if exists {
					j--
					continue
				}
				keys[j] = randKey
				delete(verificationMap, randKey)
			}

			_, err := m.DeleteBatch(&keys, batchSize)
			if err != nil {
				t.Fatal(err)
			}

		case 2:
			// Add

			// Get random set of existing keys
			for j := 0; j < batchSize; j++ {
				randKey := *randKey()
				exists := false
				for _, v := range keys {
					if v == randKey {
						exists = true
					}
				}
				if exists {
					j--
					continue
				}
				keys[j] = randKey
			}

			for j := 0; j < batchSize; j++ {
				// Gen new value
				values[j] = rand.Uint64()

				// Update value in verification map
				verificationMap[keys[j]] = values[j]
			}

			_, err := m.SetBatch(&keys, &values, bpfsys.BPFMapElemNoExists, batchSize)
			if err != nil {
				t.Fatal(err)
			}
		}

		verify()
	}
}

func TestLPMKeyFromNetwork(t *testing.T) {
	cases := []struct {
		Name     string
		CIDR     string
		Expected LPMTrieKey
	}{
		{
			Name: "IPv4 happy path",
			CIDR: "127.0.0.1/32",
			Expected: &LPMTrieIPv4Key{
				Address: [4]byte{127, 0, 0, 1},
				Prefix:  32,
			},
		},
		{
			Name: "IPv4 happy path 2",
			CIDR: "192.168.12.0/24",
			Expected: &LPMTrieIPv4Key{
				Address: [4]byte{192, 168, 12, 0},
				Prefix:  24,
			},
		},
		{
			Name: "IPv6 happy path",
			CIDR: "::1/128",
			Expected: &LPMTrieIPv6Key{
				Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				Prefix:  128,
			},
		},
		{
			Name: "IPv6 happy path 2",
			CIDR: "::192.168.12.0/120",
			Expected: &LPMTrieIPv6Key{
				Address: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 12, 0},
				Prefix:  120,
			},
		},
	}

	for _, testCase := range cases {
		t.Run(t.Name()+"_"+testCase.Name, func(tt *testing.T) {
			_, ipNet, err := net.ParseCIDR(testCase.CIDR)
			if err != nil {
				tt.Fatal(err)
			}

			key := LPMKeyFromNetwork(*ipNet)
			if !reflect.DeepEqual(key, testCase.Expected) {
				tt.Fatal("keys not equal")
			}
		})
	}
}
