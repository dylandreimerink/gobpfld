//go:build bpftests
// +build bpftests

package gobpfld

import (
	"math/rand"
	"testing"

	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

func TestStackMap(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapStack) {
		t.Skip("skipping test, current kernel version has no support for stack maps")
	}

	const maxEntries = 20
	stack := StackMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_STACK,
				KeySize:    0,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	err := stack.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	validationMap := make([]int64, maxEntries)
	for i := 0; i < maxEntries; i++ {
		val := rand.Int63()
		err = stack.Push(&val)
		validationMap[i] = int64(val)
		if err != nil {
			t.Fatal(err)
		}
	}

	var v int64
	err = stack.Peek(&v)
	if err != nil {
		t.Fatal(err)
	}

	if v != validationMap[len(validationMap)-1] {
		t.Fatalf("invalid peek, got: %d, expected: %d", v, validationMap[len(validationMap)-1])
	}

	for i := maxEntries - 1; i >= 0; i-- {
		var v int64
		err = stack.Pop(&v)
		if err != nil {
			t.Fatal(err)
		}

		if v != validationMap[i] {
			t.Fatalf("invalid pop, got: %d, expected: %d", v, validationMap[i])
		}
	}
}

func TestStackMapIterator(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapStack) {
		t.Skip("skipping test, current kernel version has no support for stack maps")
	}

	const maxEntries = 20
	stack := StackMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_STACK,
				KeySize:    0,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	err := stack.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()

	validationMap := make([]int64, maxEntries)
	for i := 0; i < maxEntries; i++ {
		val := rand.Int63()
		err = stack.Push(&val)
		validationMap[i] = int64(val)
		if err != nil {
			t.Fatal(err)
		}
	}

	i := maxEntries - 1
	var v int64
	err = MapIterForEach(stack.Iterator(), nil, &v, func(_, _ interface{}) error {
		if v != validationMap[i] {
			t.Fatalf("invalid pop, got: %d, expected: %d", v, validationMap[i])
		}
		i--

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
