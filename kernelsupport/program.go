package kernelsupport

import (
	"fmt"
	"strings"
)

// ProgramSupport is a flagset that describes which programs types are supported
type ProgramSupport uint64

// TODO add comments
const (
	// 3.19
	KFeatProgSocketFilter ProgramSupport = 1 << iota
	// 4.1
	KFeatProgKProbe
	// 4.1
	KFeatProgSchedCLS
	// 4.1
	KFeatProgSchedACT
	// 4.7
	KFeatProgTracepoint
	// 4.8
	KFeatProgXDP
	// 4.9
	KFeatProgPerfEvent
	// 4.10
	KFeatProgCGroupSKB
	// 4.10
	KFeatProgCGroupSocket
	// 4.10
	KFeatProgLWTIn
	KFeatProgLWTOut
	KFeatProgLWTXmit
	// 4.13
	KFeatProgSocketOps
	// 4.14
	KFeatProgSKSKB
	// 4.15
	KFeatProgCGroupDevice
	// 4.17
	KFeatProgSKMsg
	// 4.17
	KFeatProgRawTracepoint
	// 4.17
	KFeatProgCGroupSocketAddr
	// 4.18
	KFeatProgLWTSeg6Local
	// 4.18
	KFeatProgLIRCMode2
	// 4.19
	KFeatProgSKReusePort
	// 4.20
	KFeatProgFlowDissector
	// 5.2
	KFeatProgCGroupSysctl
	// 5.2
	KFeatProgRawTracepointWritable
	// 5.3
	KFeatProgCgroupSocketOpt
	// 5.5
	KFeatProgTracing
	// 5.6
	KFeatProgStructOps
	// 5.6
	KFeatProgExt
	// 5.7
	KFeatProgLSM
	// 5.9
	KFeatProgSKLookup

	// An end marker for enumeration, not an actual feature flag
	kFeatProgMax
)

// Has returns true if 'ps' has all the specified flags
func (ps ProgramSupport) Has(flags ProgramSupport) bool {
	return ps&flags == flags
}

var programSupportToString = map[ProgramSupport]string{
	KFeatProgSocketFilter:          "Socket filter",
	KFeatProgKProbe:                "KProbe",
	KFeatProgSchedCLS:              "TC classifier",
	KFeatProgSchedACT:              "TC action",
	KFeatProgTracepoint:            "Tracepoint",
	KFeatProgXDP:                   "XDP",
	KFeatProgPerfEvent:             "Perf event",
	KFeatProgCGroupSKB:             "CGroup SKB",
	KFeatProgCGroupSocket:          "CGroup Socket",
	KFeatProgLWTIn:                 "LWT in",
	KFeatProgLWTOut:                "LWT out",
	KFeatProgLWTXmit:               "LWT xmit",
	KFeatProgSocketOps:             "Socket operations",
	KFeatProgSKSKB:                 "SK SKB",
	KFeatProgCGroupDevice:          "CGroup device",
	KFeatProgSKMsg:                 "SK messag",
	KFeatProgRawTracepoint:         "Raw tracepoint",
	KFeatProgCGroupSocketAddr:      "CGroup socket addr",
	KFeatProgLWTSeg6Local:          "LWT seg6 local",
	KFeatProgLIRCMode2:             "LIRC mode2",
	KFeatProgSKReusePort:           "SK reuse port",
	KFeatProgFlowDissector:         "Flow dissector",
	KFeatProgCGroupSysctl:          "CGroup sysctl",
	KFeatProgRawTracepointWritable: "Raw tracepoint writable",
	KFeatProgCgroupSocketOpt:       "Cgroup socket options",
	KFeatProgTracing:               "Tracing",
	KFeatProgStructOps:             "Struct operations",
	KFeatProgExt:                   "Extentsion",
	KFeatProgLSM:                   "LSM",
	KFeatProgSKLookup:              "SK lookup",
}

func (ps ProgramSupport) String() string {
	var progs []string
	for i := ProgramSupport(1); i < kFeatProgMax; i = i << 1 {
		// If this flag is set
		if ps&i > 0 {
			progStr := programSupportToString[i]
			if progStr == "" {
				progStr = fmt.Sprintf("missing program str(%d)", i)
			}
			progs = append(progs, progStr)
		}
	}

	if len(progs) == 0 {
		return "No support"
	}

	if len(progs) == 1 {
		return progs[0]
	}

	return strings.Join(progs, ", ")
}
