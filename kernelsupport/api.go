package kernelsupport

import (
	"fmt"
	"strings"
)

// APISupport is a flagset which describes which features related to the bpf syscall API are supported
type APISupport uint64

// TODO add comments
const (
	KFeatAPIMapLookup APISupport = 1 << iota
	KFeatAPIMapUpdate
	KFeatAPIMapDelete
	KFeatAPIMapGetNext
	KFeatAPIMapGetNextNull
	KFeatAPIMapNumaCreate
	KFeatAPIMapSyscallRW
	KFeatAPIMapName
	KFeatAPIMapLookupAndDelete
	KFeatAPIMapZeroSeed
	KFeatAPIMapLock
	KFeatAPIMapBPFRW
	KFeatAPIMapFreeze
	KFeatAPIMapMMap
	KFeatAPIMapLookupBatch
	KFeatAPIMapUpdateBatch
	KFeatAPIMapDeleteBatch
	KFeatAPIMapLookupAndDeleteBatch

	// TODO API commands other than map commands like 'get info by fd'

	// An end marker for enumeration, not an actual feature flag
	kFeatAPIMax
)

// Has returns true if 'as' has all the specified flags
func (as APISupport) Has(flags APISupport) bool {
	return as&flags == flags
}

var apiSupportToString = map[APISupport]string{
	KFeatAPIMapLookup:               "Map lookup",
	KFeatAPIMapUpdate:               "Map update",
	KFeatAPIMapDelete:               "Map delete",
	KFeatAPIMapGetNext:              "Map get next",
	KFeatAPIMapGetNextNull:          "Map get next null",
	KFeatAPIMapNumaCreate:           "Map NUMA create",
	KFeatAPIMapSyscallRW:            "Map syscall R/W",
	KFeatAPIMapName:                 "Map name",
	KFeatAPIMapLookupAndDelete:      "Map lookup and delete",
	KFeatAPIMapZeroSeed:             "Map zero seed",
	KFeatAPIMapLock:                 "Map lock",
	KFeatAPIMapBPFRW:                "Map BPF R/W",
	KFeatAPIMapFreeze:               "Map freeze",
	KFeatAPIMapMMap:                 "Map MMap",
	KFeatAPIMapLookupBatch:          "Map lookup batch",
	KFeatAPIMapUpdateBatch:          "Map update batch",
	KFeatAPIMapDeleteBatch:          "Map delete batch",
	KFeatAPIMapLookupAndDeleteBatch: "Map lookup and delete batch",
}

func (ms APISupport) String() string {
	var apis []string
	for i := APISupport(1); i < kFeatAPIMax; i = i << 1 {
		// If this flag is set
		if ms&i > 0 {
			apiStr := apiSupportToString[i]
			if apiStr == "" {
				apiStr = fmt.Sprintf("missing api str(%d)", i)
			}
			apis = append(apis, apiStr)
		}
	}

	if len(apis) == 0 {
		return "No support"
	}

	if len(apis) == 1 {
		return apis[0]
	}

	return strings.Join(apis, ", ")
}
