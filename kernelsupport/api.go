package kernelsupport

import (
	"fmt"
	"strings"
)

// APISupport is a flagset which describes which features related to the bpf syscall API are supported
type APISupport uint64

// TODO add comments
const (
	// KFeatAPIBasic includes: map create, map lookup, map update, map delete, map getnext
	// prog load
	KFeatAPIBasic APISupport = 1 << iota
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
	// 4.4 OBJ_PIN and OBJ_GET
	KFeatAPIObjPinGet
	// 4.10 PROG_ATTACH and PROG_DETACH
	KFeatAPIProgramAttachDetach
	// 4.12
	KFeatAPIProgramTestRun
	// 4.13
	KFeatAPIProgramGetNextID
	// 4.13
	KFeatAPIMapGetNextID
	// 4.13
	KFeatAPIProgramGetFDByID
	// 4.13
	KFeatAPIMapGetFDByID
	// 4.13
	KFeatAPIObjectGetInfoByFD
	// 4.15
	KFeatAPIProgramQuery
	// 4.17
	KFeatAPIRawTracepointOpen
	// 4.18
	KFeatAPIBTFLoad
	// 4.18
	KFeatAPIBTFGetFDByID
	// 4.18
	KFeatAPITaskFDQuery
	// 5.4
	KFeatAPIBTFGetNextID
	// 5.7
	KFeatAPILinkCreate
	// 5.7
	KFeatAPILinkUpdate
	// 5.8
	KFeatAPILinkGetFDByID
	// 5.8
	KFeatAPILinkGetNextID
	// 5.8
	KFeatAPIEnableStats
	// 5.8
	KFeatAPIIterCreate
	// 5.9
	KFeatAPILinkDetach
	// 5.10
	KFeatAPIProgBindMap

	// An end marker for enumeration, not an actual feature flag
	kFeatAPIMax //nolint:revive // leading k is used to stay consistent with exported vars
)

// Has returns true if 'as' has all the specified flags
func (as APISupport) Has(flags APISupport) bool {
	return as&flags == flags
}

var apiSupportToString = map[APISupport]string{
	KFeatAPIBasic:                   "Map create, map lookup, map update, map getnext, prog load",
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
	KFeatAPIObjPinGet:               "Object pin/get",
	KFeatAPIProgramAttachDetach:     "Program attach/detach",
	KFeatAPIProgramTestRun:          "Program test run",
	KFeatAPIProgramGetNextID:        "Program get next ID",
	KFeatAPIMapGetNextID:            "Map get next ID",
	KFeatAPIProgramGetFDByID:        "Program get FD by ID",
	KFeatAPIMapGetFDByID:            "Map get FD by ID",
	KFeatAPIObjectGetInfoByFD:       "Object get info by FD",
	KFeatAPIProgramQuery:            "Program query",
	KFeatAPIRawTracepointOpen:       "Raw tracepoint open",
	KFeatAPIBTFLoad:                 "BTF load",
	KFeatAPIBTFGetFDByID:            "BTF get FD by ID",
	KFeatAPITaskFDQuery:             "Task FD query",
	KFeatAPIBTFGetNextID:            "BTF get next ID",
	KFeatAPILinkCreate:              "Link create",
	KFeatAPILinkUpdate:              "Link update",
	KFeatAPILinkGetFDByID:           "Link get FD by ID",
	KFeatAPILinkGetNextID:           "Link get next ID",
	KFeatAPIEnableStats:             "Enable stats",
	KFeatAPIIterCreate:              "Iterator create",
	KFeatAPILinkDetach:              "Link detach",
	KFeatAPIProgBindMap:             "Prog bind map",
}

func (as APISupport) String() string {
	var apis []string
	for i := APISupport(1); i < kFeatAPIMax; i = i << 1 {
		// If this flag is set
		if as&i > 0 {
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
