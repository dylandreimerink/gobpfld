package kernelsupport

import (
	"fmt"
	"strings"
)

// MapSupport is a flagset that describes which map types are supported
type MapSupport uint64

// TODO add comments
const (
	// KFeatMapHash means the kernel supports Hash maps
	KFeatMapHash MapSupport = 1 << iota
	KFeatMapArray
	KFeatMapTailCall
	KFeatMapPerfEvent
	KFeatMapPerCPUHash
	KFeatMapPerCPUArray
	KFeatMapStackTrace
	KFeatMapCGroupArray
	KFeatMapLRUHash
	KFeatMapLRUPerCPUHash
	KFeatMapLPMTrie
	KFeatMapArrayOfMaps
	KFeatMapHashOfMaps
	KFeatMapNetdevArray
	KFeatMapSocketArray
	KFeatMapCPU
	KFeatMapAFXDP
	KFeatMapSocketHash
	KFeatMapCGroupStorage
	KFeatMapReuseportSocketArray
	KFeatMapPerCPUCGroupStorage
	KFeatMapQueue
	KFeatMapStack
	KFeatMapSocketLocalStorage
	KFeatMapNetdevHash
	KFeatMapStructOps
	KFeatMapRingBuffer
	KFeatMapINodeStorage
	KFeatMapTaskStorage

	// An end marker for enumeration, not an actual feature flag
	kFeatMapMax //nolint:revive // leading k is used to stay consistent with exported vars
)

// Has returns true if 'ms' has all the specified flags
func (ms MapSupport) Has(flags MapSupport) bool {
	return ms&flags == flags
}

var mapSupportToString = map[MapSupport]string{
	KFeatMapHash:                 "Hash",
	KFeatMapArray:                "Array",
	KFeatMapTailCall:             "Tail call",
	KFeatMapPerfEvent:            "Perf event",
	KFeatMapPerCPUHash:           "Per CPU hash",
	KFeatMapPerCPUArray:          "Per CPU array",
	KFeatMapStackTrace:           "Stack trace",
	KFeatMapCGroupArray:          "CGroup array",
	KFeatMapLRUHash:              "LRU hash",
	KFeatMapLRUPerCPUHash:        "LRU per CPU hash",
	KFeatMapLPMTrie:              "LPM trie",
	KFeatMapArrayOfMaps:          "Array of maps",
	KFeatMapHashOfMaps:           "Hash of maps",
	KFeatMapNetdevArray:          "Netdev array",
	KFeatMapSocketArray:          "Socket array",
	KFeatMapCPU:                  "CPU",
	KFeatMapAFXDP:                "AF_XDP",
	KFeatMapSocketHash:           "Socket hash",
	KFeatMapCGroupStorage:        "CGroup storage",
	KFeatMapReuseportSocketArray: "Reuseport socket array",
	KFeatMapPerCPUCGroupStorage:  "Per CPU cgroup storage",
	KFeatMapQueue:                "Queue",
	KFeatMapStack:                "Stack",
	KFeatMapSocketLocalStorage:   "Socket local storage",
	KFeatMapNetdevHash:           "Netdev hash",
	KFeatMapStructOps:            "Struct ops",
	KFeatMapRingBuffer:           "Ring buffer",
	KFeatMapINodeStorage:         "INode storage",
	KFeatMapTaskStorage:          "Task storage",
}

func (ms MapSupport) String() string {
	var maps []string
	for i := MapSupport(1); i < kFeatMapMax; i = i << 1 {
		// If this flag is set
		if ms&i > 0 {
			mapStr := mapSupportToString[i]
			if mapStr == "" {
				mapStr = fmt.Sprintf("missing map str(%d)", i)
			}
			maps = append(maps, mapStr)
		}
	}

	if len(maps) == 0 {
		return "No support"
	}

	if len(maps) == 1 {
		return maps[0]
	}

	return strings.Join(maps, ", ")
}
