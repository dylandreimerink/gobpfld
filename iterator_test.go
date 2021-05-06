package gobpfld_test

import (
	"testing"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

const mapSize = 100000

var testMap *gobpfld.BPFGenericMap

func getTestMap() *gobpfld.BPFGenericMap {
	if testMap != nil {
		return testMap
	}

	testMap = &gobpfld.BPFGenericMap{
		AbstractMap: gobpfld.AbstractMap{
			Name: gobpfld.MustNewObjName("xdp_stats_map"),
			Definition: gobpfld.BPFMapDef{
				Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
				KeySize:    4, // SizeOf(uint32)
				ValueSize:  8, // SizeOf(uint64)
				MaxEntries: mapSize,
			},
		},
	}

	err := testMap.Load()
	if err != nil {
		panic(err)
	}

	for i := uint32(0); i < mapSize; i++ {
		val := uint64(i * 10)
		err = testMap.Set(&i, &val, bpfsys.BPFMapElemAny)
		if err != nil {
			panic(err)
		}
	}

	return testMap
}

func benchmarkBatchMapIterator(bufSize int, b *testing.B) {
	tMap := getTestMap()

	b.ResetTimer()

	// run the Fib function b.N times
	for n := 0; n < b.N; n++ {
		iter := gobpfld.BatchLookupIterator{
			BPFMap:  tMap,
			BufSize: bufSize,
		}

		var (
			key   uint32
			value uint64
		)
		err := iter.Init(&key, &value)
		if err != nil {
			b.Error(err)
		}

		var updated bool
		for updated, err = iter.Next(); updated && err == nil; updated, err = iter.Next() {
		}
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkBatchMapIterator16(b *testing.B) {
	benchmarkBatchMapIterator(16, b)
}

func BenchmarkBatchMapIterator64(b *testing.B) {
	benchmarkBatchMapIterator(64, b)
}

func BenchmarkBatchMapIterator256(b *testing.B) {
	benchmarkBatchMapIterator(256, b)
}

func BenchmarkBatchMapIterator1024(b *testing.B) {
	benchmarkBatchMapIterator(1024, b)
}

func BenchmarkBatchMapIterator4096(b *testing.B) {
	benchmarkBatchMapIterator(4096, b)
}

func BenchmarkBatchMapIterator16384(b *testing.B) {
	benchmarkBatchMapIterator(16384, b)
}
