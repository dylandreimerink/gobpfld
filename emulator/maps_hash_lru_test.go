package emulator

import (
	"crypto/sha256"
	"testing"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

func TestEmulatedHashMapLRU(t *testing.T) {
	m := HashMapLRU{
		Name: "LRU map",
		Def: gobpfld.BPFMapDef{
			Type:       bpftypes.BPF_MAP_TYPE_LRU_HASH,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 5,
		},
	}

	err := m.Init()
	if err != nil {
		t.Fatal(err)
	}

	makeMemPtr := func(i int) *MemoryPtr {
		im := newIMM(int64(i))
		return &MemoryPtr{
			Memory: &ValueMemory{
				Mapping: []RegisterValue{
					im,
					im,
					im,
					im,
				},
			},
		}
	}

	k1 := makeMemPtr(1)
	k2 := makeMemPtr(2)
	k3 := makeMemPtr(3)
	k4 := makeMemPtr(4)
	k5 := makeMemPtr(5)
	k6 := makeMemPtr(6)

	// Add 5 values, filling the map
	_, err = m.Update(k1, makeMemPtr(11), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(k2, makeMemPtr(12), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(k3, makeMemPtr(13), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(k4, makeMemPtr(14), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Update(k5, makeMemPtr(15), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}

	// Key 1 was added first, so it is least recently used.

	// Lookup 1 and 2, no 3 should be least recently used
	_, err = m.Lookup(k1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Lookup(k2)
	if err != nil {
		t.Fatal(err)
	}

	// Insert a sixth element, which should overwrite 3
	_, err = m.Update(k6, makeMemPtr(16), bpfsys.BPFMapElemAny)
	if err != nil {
		t.Fatal(err)
	}

	kh := func(key *MemoryPtr) hashKey {
		b, err := key.ReadRange(0, 4)
		if err != nil {
			t.Fatal(err)
		}

		return sha256.Sum256(b)
	}

	k1h := kh(k1)
	k2h := kh(k2)
	k4h := kh(k4)
	k5h := kh(k5)
	k6h := kh(k6)

	// 6 should be the most recent since it was added last
	if m.UsageList[0] != k6h {
		t.Fatal("usage list 0 != k6h")
	}
	// 2 should be second due to the most recent lookup
	if m.UsageList[1] != k2h {
		t.Fatal("usage list 0 != k2h")
	}
	// 1 should be third due to the lookup
	if m.UsageList[2] != k1h {
		t.Fatal("usage list 0 != k1h")
	}
	if m.UsageList[3] != k5h {
		t.Fatal("usage list 0 != k5h")
	}
	if m.UsageList[4] != k4h {
		t.Fatal("usage list 0 != k4h")
	}
}
