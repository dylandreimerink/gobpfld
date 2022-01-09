//go:build bpftests
// +build bpftests

package gobpfld

import (
	"math/rand"
	"testing"

	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

func TestQueueMap(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapQueue) {
		t.Skip("skipping test, current kernel version has no support for queue maps")
	}

	const maxEntries = 20
	queue := QueueMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_QUEUE,
				KeySize:    0,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	err := queue.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()

	validationMap := make([]int64, maxEntries)
	for i := 0; i < maxEntries; i++ {
		val := rand.Int63()
		err = queue.Enqueue(&val)
		validationMap[i] = int64(val)
		if err != nil {
			t.Fatal(err)
		}
	}

	var v int64
	err = queue.Peek(&v)
	if err != nil {
		t.Fatal(err)
	}

	if v != validationMap[0] {
		t.Fatalf("invalid peek, got: %d, expected: %d", v, validationMap[0])
	}

	for i := 0; i >= maxEntries; i-- {
		var v int64
		err = queue.Dequeue(&v)
		if err != nil {
			t.Fatal(err)
		}

		if v != validationMap[i] {
			t.Fatalf("invalid dequeue, got: %d, expected: %d", v, validationMap[i])
		}
	}
}

func TestQueueMapIterator(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapQueue) {
		t.Skip("skipping test, current kernel version has no support for queue maps")
	}

	const maxEntries = 20
	queue := QueueMap{
		AbstractMap: AbstractMap{
			Name: MustNewObjName("test"),
			Definition: BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_QUEUE,
				KeySize:    0,
				ValueSize:  sizeOfUint64,
				MaxEntries: maxEntries,
			},
		},
	}

	err := queue.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()

	validationMap := make([]int64, maxEntries)
	for i := 0; i < maxEntries; i++ {
		val := rand.Int63()
		err = queue.Enqueue(&val)
		validationMap[i] = int64(val)
		if err != nil {
			t.Fatal(err)
		}
	}

	i := 0
	var v int64
	err = MapIterForEach(queue.Iterator(), nil, &v, func(_, _ interface{}) error {
		if v != validationMap[i] {
			t.Fatalf("invalid dequeue, got: %d, expected: %d", v, validationMap[i])
		}
		i++

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
