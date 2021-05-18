package kernelsupport

import (
	"fmt"
	"strings"
)

// AttachSupport is a flagset that describes which attach types are supported
type AttachSupport uint64

// TODO add comments
const (
	// 3.19 Ingress and Egress
	KFeatAttachINetIngressEgress AttachSupport = 1 << iota
	// 4.10
	KFeatAttachInetSocketCreate
	// 4.13
	KFeatAttachSocketOps
	// 4.14 stream parser and stream verdict
	KFeatAttachStreamParserVerdict
	// 4.15
	KFeatAttachCGroupDevice
	// 4.17
	KFeatAttachSKMsgVerdict
	// 4.17 inet4 + inet6
	KFeatAttachCGroupInetBind
	// 4.17 inet4 + inet6
	KFeatAttachCGroupInetConnect
	// 4.17 inet4 + inet6
	KFeatAttachCGroupInetPostBind
	// 4.18 udp4 + udp6
	KFeatAttachCGroupUDPSendMsg
	// 4.18
	KFeatAttachLIRCMode2
	// 4.20
	KFeatAttachFlowDissector
	// 5.2
	KFeatAttachCGroupSysctl
	// 5.2 udp4 + udp6
	KFeatAttachCGroupUDPRecvMsg
	// 5.3 CGroupGetSocket + CGroupSetSocket
	KFeatAttachCGroupGetSetSocket
	// 5.5
	KFeatAttachTraceRawTP
	// 5.5
	KFeatAttachTraceFentry
	// 5.5
	KFeatAttachTraceFExit
	// 5.7
	KFeatAttachModifyReturn
	// 5.7
	KFeatAttachLSMMAC
	// 5.8
	KFeatAttachTraceIter
	// 5.8 inet4 + inet6
	KFeatAttachCGroupINetGetPeerName
	// 5.8 inet4 + inet6
	KFeatAttachCGroupINetGetSocketName
	// 5.8
	KFeatAttachXDPDevMap
	// 5.9
	KFeatAttachCGroupInetSocketRelease
	// 5.9
	KFeatAttachXDPCPUMap
	// 5.9
	KFeatAttachSKLookup
	// 5.9
	KFeatAttachXDP

	// An end marker for enumeration, not an actual feature flag
	kFeatAttachMax //nolint:revive // leading k is used to stay consistent with exported vars
)

// Has returns true if 'as' has all the specified flags
func (as AttachSupport) Has(flags AttachSupport) bool {
	return as&flags == flags
}

var attachSupportToString = map[AttachSupport]string{
	KFeatAttachINetIngressEgress:       "INet ingress/egress",
	KFeatAttachInetSocketCreate:        "INet socket create",
	KFeatAttachSocketOps:               "Socket operations",
	KFeatAttachStreamParserVerdict:     "Stream parser/verdict",
	KFeatAttachCGroupDevice:            "CGroup device",
	KFeatAttachSKMsgVerdict:            "SK message verdict",
	KFeatAttachCGroupInetBind:          "CGroup inet bind",
	KFeatAttachCGroupInetConnect:       "CGroup inet connect",
	KFeatAttachCGroupInetPostBind:      "CGroup inet post bind",
	KFeatAttachCGroupUDPSendMsg:        "CGroup UDP send message",
	KFeatAttachLIRCMode2:               "LIRC mode2",
	KFeatAttachFlowDissector:           "Flow dissector",
	KFeatAttachCGroupSysctl:            "CGroup sysctl",
	KFeatAttachCGroupUDPRecvMsg:        "CGroup UDP receive message",
	KFeatAttachCGroupGetSetSocket:      "CGroup get/set socket",
	KFeatAttachTraceRawTP:              "Trace raw TP",
	KFeatAttachTraceFentry:             "Trace fentry",
	KFeatAttachTraceFExit:              "Trace fexit",
	KFeatAttachModifyReturn:            "Modify return",
	KFeatAttachLSMMAC:                  "LSM MAC",
	KFeatAttachTraceIter:               "Trace iterator",
	KFeatAttachCGroupINetGetPeerName:   "CGroup inet get peer name",
	KFeatAttachCGroupINetGetSocketName: "CGroup inet get socket name",
	KFeatAttachXDPDevMap:               "XDP device map",
	KFeatAttachCGroupInetSocketRelease: "CGroup inet socket release",
	KFeatAttachXDPCPUMap:               "XDP CPU map",
	KFeatAttachSKLookup:                "SK lookup",
	KFeatAttachXDP:                     "XDP",
}

func (as AttachSupport) String() string {
	var attachTypes []string
	for i := AttachSupport(1); i < kFeatAttachMax; i = i << 1 {
		// If this flag is set
		if as&i > 0 {
			attachStr := attachSupportToString[i]
			if attachStr == "" {
				attachStr = fmt.Sprintf("missing attach str(%d)", i)
			}
			attachTypes = append(attachTypes, attachStr)
		}
	}

	if len(attachTypes) == 0 {
		return "No support"
	}

	if len(attachTypes) == 1 {
		return attachTypes[0]
	}

	return strings.Join(attachTypes, ", ")
}
