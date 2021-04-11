package bpftypes

import (
	"unsafe"
)

const (
	// The max length of an object name as defined by the linux kernel
	// The actual size of the string is 16 bytes, but the last byte must always be 0x00
	BPF_OBJ_NAME_LEN = 15
)

// BPFCommand is a enum which describes a number of different commands which can be sent to the kernel
// via the bpf syscall.
// From bpf_cmd https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L96
type BPFCommand int

const (
	BPF_MAP_CREATE BPFCommand = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	BPF_MAP_FREEZE
	BPF_BTF_GET_NEXT_ID
	BPF_MAP_LOOKUP_BATCH
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	BPF_MAP_UPDATE_BATCH
	BPF_MAP_DELETE_BATCH
	BPF_LINK_CREATE
	BPF_LINK_UPDATE
	BPF_LINK_GET_FD_BY_ID
	BPF_LINK_GET_NEXT_ID
	BPF_ENABLE_STATS
	BPF_ITER_CREATE
	BPF_LINK_DETACH
	BPF_PROG_BIND_MAP
)

var bpfCommandToStr = map[BPFCommand]string{
	BPF_MAP_CREATE:                  "BPF_MAP_CREATE",
	BPF_MAP_LOOKUP_ELEM:             "BPF_MAP_LOOKUP_ELEM",
	BPF_MAP_UPDATE_ELEM:             "BPF_MAP_UPDATE_ELEM",
	BPF_MAP_DELETE_ELEM:             "BPF_MAP_DELETE_ELEM",
	BPF_MAP_GET_NEXT_KEY:            "BPF_MAP_GET_NEXT_KEY",
	BPF_PROG_LOAD:                   "BPF_PROG_LOAD",
	BPF_OBJ_PIN:                     "BPF_OBJ_PIN",
	BPF_OBJ_GET:                     "BPF_OBJ_GET",
	BPF_PROG_ATTACH:                 "BPF_PROG_ATTACH",
	BPF_PROG_DETACH:                 "BPF_PROG_DETACH",
	BPF_PROG_TEST_RUN:               "BPF_PROG_TEST_RUN",
	BPF_PROG_GET_NEXT_ID:            "BPF_PROG_GET_NEXT_ID",
	BPF_MAP_GET_NEXT_ID:             "BPF_MAP_GET_NEXT_ID",
	BPF_PROG_GET_FD_BY_ID:           "BPF_PROG_GET_FD_BY_ID",
	BPF_MAP_GET_FD_BY_ID:            "BPF_MAP_GET_FD_BY_ID",
	BPF_OBJ_GET_INFO_BY_FD:          "BPF_OBJ_GET_INFO_BY_FD",
	BPF_PROG_QUERY:                  "BPF_PROG_QUERY",
	BPF_RAW_TRACEPOINT_OPEN:         "BPF_RAW_TRACEPOINT_OPEN",
	BPF_BTF_LOAD:                    "BPF_BTF_LOAD",
	BPF_BTF_GET_FD_BY_ID:            "BPF_BTF_GET_FD_BY_ID",
	BPF_TASK_FD_QUERY:               "BPF_TASK_FD_QUERY",
	BPF_MAP_LOOKUP_AND_DELETE_ELEM:  "BPF_MAP_LOOKUP_AND_DELETE_ELEM",
	BPF_MAP_FREEZE:                  "BPF_MAP_FREEZE",
	BPF_BTF_GET_NEXT_ID:             "BPF_BTF_GET_NEXT_ID",
	BPF_MAP_LOOKUP_BATCH:            "BPF_MAP_LOOKUP_BATCH",
	BPF_MAP_LOOKUP_AND_DELETE_BATCH: "BPF_MAP_LOOKUP_AND_DELETE_BATCH",
	BPF_MAP_UPDATE_BATCH:            "BPF_MAP_UPDATE_BATCH",
	BPF_MAP_DELETE_BATCH:            "BPF_MAP_DELETE_BATCH",
	BPF_LINK_CREATE:                 "BPF_LINK_CREATE",
	BPF_LINK_UPDATE:                 "BPF_LINK_UPDATE",
	BPF_LINK_GET_FD_BY_ID:           "BPF_LINK_GET_FD_BY_ID",
	BPF_LINK_GET_NEXT_ID:            "BPF_LINK_GET_NEXT_ID",
	BPF_ENABLE_STATS:                "BPF_ENABLE_STATS",
	BPF_ITER_CREATE:                 "BPF_ITER_CREATE",
	BPF_LINK_DETACH:                 "BPF_LINK_DETACH",
	BPF_PROG_BIND_MAP:               "BPF_PROG_BIND_MAP",
}

func (cmd BPFCommand) String() string {
	str := bpfCommandToStr[cmd]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// BPFMapType is an enum type which describes a type of map
// From bpf_map_type https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L136
type BPFMapType uint32

const (
	BPF_MAP_TYPE_UNSPEC BPFMapType = iota
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	BPF_MAP_TYPE_QUEUE
	BPF_MAP_TYPE_STACK
	BPF_MAP_TYPE_SK_STORAGE
	BPF_MAP_TYPE_DEVMAP_HASH
	BPF_MAP_TYPE_STRUCT_OPS
	BPF_MAP_TYPE_RINGBUF
	BPF_MAP_TYPE_INODE_STORAGE
	BPF_MAP_TYPE_TASK_STORAGE
)

var bpfMapTypeToStr = map[BPFMapType]string{
	BPF_MAP_TYPE_UNSPEC:                "BPF_MAP_TYPE_UNSPEC",
	BPF_MAP_TYPE_HASH:                  "BPF_MAP_TYPE_HASH",
	BPF_MAP_TYPE_ARRAY:                 "BPF_MAP_TYPE_ARRAY",
	BPF_MAP_TYPE_PROG_ARRAY:            "BPF_MAP_TYPE_PROG_ARRAY",
	BPF_MAP_TYPE_PERF_EVENT_ARRAY:      "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
	BPF_MAP_TYPE_PERCPU_HASH:           "BPF_MAP_TYPE_PERCPU_HASH",
	BPF_MAP_TYPE_PERCPU_ARRAY:          "BPF_MAP_TYPE_PERCPU_ARRAY",
	BPF_MAP_TYPE_STACK_TRACE:           "BPF_MAP_TYPE_STACK_TRACE",
	BPF_MAP_TYPE_CGROUP_ARRAY:          "BPF_MAP_TYPE_CGROUP_ARRAY",
	BPF_MAP_TYPE_LRU_HASH:              "BPF_MAP_TYPE_LRU_HASH",
	BPF_MAP_TYPE_LRU_PERCPU_HASH:       "BPF_MAP_TYPE_LRU_PERCPU_HASH",
	BPF_MAP_TYPE_LPM_TRIE:              "BPF_MAP_TYPE_LPM_TRIE",
	BPF_MAP_TYPE_ARRAY_OF_MAPS:         "BPF_MAP_TYPE_ARRAY_OF_MAPS",
	BPF_MAP_TYPE_HASH_OF_MAPS:          "BPF_MAP_TYPE_HASH_OF_MAPS",
	BPF_MAP_TYPE_DEVMAP:                "BPF_MAP_TYPE_DEVMAP",
	BPF_MAP_TYPE_SOCKMAP:               "BPF_MAP_TYPE_SOCKMAP",
	BPF_MAP_TYPE_CPUMAP:                "BPF_MAP_TYPE_CPUMAP",
	BPF_MAP_TYPE_XSKMAP:                "BPF_MAP_TYPE_XSKMAP",
	BPF_MAP_TYPE_SOCKHASH:              "BPF_MAP_TYPE_SOCKHASH",
	BPF_MAP_TYPE_CGROUP_STORAGE:        "BPF_MAP_TYPE_CGROUP_STORAGE",
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:   "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
	BPF_MAP_TYPE_QUEUE:                 "BPF_MAP_TYPE_QUEUE",
	BPF_MAP_TYPE_STACK:                 "BPF_MAP_TYPE_STACK",
	BPF_MAP_TYPE_SK_STORAGE:            "BPF_MAP_TYPE_SK_STORAGE",
	BPF_MAP_TYPE_DEVMAP_HASH:           "BPF_MAP_TYPE_DEVMAP_HASH",
	BPF_MAP_TYPE_STRUCT_OPS:            "BPF_MAP_TYPE_STRUCT_OPS",
	BPF_MAP_TYPE_RINGBUF:               "BPF_MAP_TYPE_RINGBUF",
	BPF_MAP_TYPE_INODE_STORAGE:         "BPF_MAP_TYPE_INODE_STORAGE",
	BPF_MAP_TYPE_TASK_STORAGE:          "BPF_MAP_TYPE_TASK_STORAGE",
}

func (mt BPFMapType) String() string {
	str := bpfMapTypeToStr[mt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// From bpf_prog_type https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L177
type BPFProgType uint32

const (
	BPF_PROG_TYPE_UNSPEC BPFProgType = iota
	BPF_PROG_TYPE_SOCKET_FILTER
	BPF_PROG_TYPE_KPROBE
	BPF_PROG_TYPE_SCHED_CLS
	BPF_PROG_TYPE_SCHED_ACT
	BPF_PROG_TYPE_TRACEPOINT
	BPF_PROG_TYPE_XDP
	BPF_PROG_TYPE_PERF_EVENT
	BPF_PROG_TYPE_CGROUP_SKB
	BPF_PROG_TYPE_CGROUP_SOCK
	BPF_PROG_TYPE_LWT_IN
	BPF_PROG_TYPE_LWT_OUT
	BPF_PROG_TYPE_LWT_XMIT
	BPF_PROG_TYPE_SOCK_OPS
	BPF_PROG_TYPE_SK_SKB
	BPF_PROG_TYPE_CGROUP_DEVICE
	BPF_PROG_TYPE_SK_MSG
	BPF_PROG_TYPE_RAW_TRACEPOINT
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPF_PROG_TYPE_LIRC_MODE2
	BPF_PROG_TYPE_SK_REUSEPORT
	BPF_PROG_TYPE_FLOW_DISSECTOR
	BPF_PROG_TYPE_CGROUP_SYSCTL
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPF_PROG_TYPE_TRACING
	BPF_PROG_TYPE_STRUCT_OPS
	BPF_PROG_TYPE_EXT
	BPF_PROG_TYPE_LSM
	BPF_PROG_TYPE_SK_LOOKUP
)

var bpfProgTypeToStr = map[BPFProgType]string{
	BPF_PROG_TYPE_UNSPEC:                  "BPF_PROG_TYPE_UNSPEC",
	BPF_PROG_TYPE_SOCKET_FILTER:           "BPF_PROG_TYPE_SOCKET_FILTER",
	BPF_PROG_TYPE_KPROBE:                  "BPF_PROG_TYPE_KPROBE",
	BPF_PROG_TYPE_SCHED_CLS:               "BPF_PROG_TYPE_SCHED_CLS",
	BPF_PROG_TYPE_SCHED_ACT:               "BPF_PROG_TYPE_SCHED_ACT",
	BPF_PROG_TYPE_TRACEPOINT:              "BPF_PROG_TYPE_TRACEPOINT",
	BPF_PROG_TYPE_XDP:                     "BPF_PROG_TYPE_XDP",
	BPF_PROG_TYPE_PERF_EVENT:              "BPF_PROG_TYPE_PERF_EVENT",
	BPF_PROG_TYPE_CGROUP_SKB:              "BPF_PROG_TYPE_CGROUP_SKB",
	BPF_PROG_TYPE_CGROUP_SOCK:             "BPF_PROG_TYPE_CGROUP_SOCK",
	BPF_PROG_TYPE_LWT_IN:                  "BPF_PROG_TYPE_LWT_IN",
	BPF_PROG_TYPE_LWT_OUT:                 "BPF_PROG_TYPE_LWT_OUT",
	BPF_PROG_TYPE_LWT_XMIT:                "BPF_PROG_TYPE_LWT_XMIT",
	BPF_PROG_TYPE_SOCK_OPS:                "BPF_PROG_TYPE_SOCK_OPS",
	BPF_PROG_TYPE_SK_SKB:                  "BPF_PROG_TYPE_SK_SKB",
	BPF_PROG_TYPE_CGROUP_DEVICE:           "BPF_PROG_TYPE_CGROUP_DEVICE",
	BPF_PROG_TYPE_SK_MSG:                  "BPF_PROG_TYPE_SK_MSG",
	BPF_PROG_TYPE_RAW_TRACEPOINT:          "BPF_PROG_TYPE_RAW_TRACEPOINT",
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR:        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
	BPF_PROG_TYPE_LWT_SEG6LOCAL:           "BPF_PROG_TYPE_LWT_SEG6LOCAL",
	BPF_PROG_TYPE_LIRC_MODE2:              "BPF_PROG_TYPE_LIRC_MODE2",
	BPF_PROG_TYPE_SK_REUSEPORT:            "BPF_PROG_TYPE_SK_REUSEPORT",
	BPF_PROG_TYPE_FLOW_DISSECTOR:          "BPF_PROG_TYPE_FLOW_DISSECTOR",
	BPF_PROG_TYPE_CGROUP_SYSCTL:           "BPF_PROG_TYPE_CGROUP_SYSCTL",
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
	BPF_PROG_TYPE_CGROUP_SOCKOPT:          "BPF_PROG_TYPE_CGROUP_SOCKOPT",
	BPF_PROG_TYPE_TRACING:                 "BPF_PROG_TYPE_TRACING",
	BPF_PROG_TYPE_STRUCT_OPS:              "BPF_PROG_TYPE_STRUCT_OPS",
	BPF_PROG_TYPE_EXT:                     "BPF_PROG_TYPE_EXT",
	BPF_PROG_TYPE_LSM:                     "BPF_PROG_TYPE_LSM",
	BPF_PROG_TYPE_SK_LOOKUP:               "BPF_PROG_TYPE_SK_LOOKUP",
}

func (pt BPFProgType) String() string {
	str := bpfProgTypeToStr[pt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// From bpf_attach_type https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L211
type BPFAttachType uint32

const (
	BPF_CGROUP_INET_INGRESS BPFAttachType = iota
	BPF_CGROUP_INET_EGRESS
	BPF_CGROUP_INET_SOCK_CREATE
	BPF_CGROUP_SOCK_OPS
	BPF_SK_SKB_STREAM_PARSER
	BPF_SK_SKB_STREAM_VERDICT
	BPF_CGROUP_DEVICE
	BPF_SK_MSG_VERDICT
	BPF_CGROUP_INET4_BIND
	BPF_CGROUP_INET6_BIND
	BPF_CGROUP_INET4_CONNECT
	BPF_CGROUP_INET6_CONNECT
	BPF_CGROUP_INET4_POST_BIND
	BPF_CGROUP_INET6_POST_BIND
	BPF_CGROUP_UDP4_SENDMSG
	BPF_CGROUP_UDP6_SENDMSG
	BPF_LIRC_MODE2
	BPF_FLOW_DISSECTOR
	BPF_CGROUP_SYSCTL
	BPF_CGROUP_UDP4_RECVMSG
	BPF_CGROUP_UDP6_RECVMSG
	BPF_CGROUP_GETSOCKOPT
	BPF_CGROUP_SETSOCKOPT
	BPF_TRACE_RAW_TP
	BPF_TRACE_FENTRY
	BPF_TRACE_FEXIT
	BPF_MODIFY_RETURN
	BPF_LSM_MAC
	BPF_TRACE_ITER
	BPF_CGROUP_INET4_GETPEERNAME
	BPF_CGROUP_INET6_GETPEERNAME
	BPF_CGROUP_INET4_GETSOCKNAME
	BPF_CGROUP_INET6_GETSOCKNAME
	BPF_XDP_DEVMAP
	BPF_CGROUP_INET_SOCK_RELEASE
	BPF_XDP_CPUMAP
	BPF_SK_LOOKUP
	BPF_XDP
)

var bpfAttachTypeToStr = map[BPFAttachType]string{
	BPF_CGROUP_INET_INGRESS:      "BPF_CGROUP_INET_INGRESS",
	BPF_CGROUP_INET_EGRESS:       "BPF_CGROUP_INET_EGRESS",
	BPF_CGROUP_INET_SOCK_CREATE:  "BPF_CGROUP_INET_SOCK_CREATE",
	BPF_CGROUP_SOCK_OPS:          "BPF_CGROUP_SOCK_OPS",
	BPF_SK_SKB_STREAM_PARSER:     "BPF_SK_SKB_STREAM_PARSER",
	BPF_SK_SKB_STREAM_VERDICT:    "BPF_SK_SKB_STREAM_VERDICT",
	BPF_CGROUP_DEVICE:            "BPF_CGROUP_DEVICE",
	BPF_SK_MSG_VERDICT:           "BPF_SK_MSG_VERDICT",
	BPF_CGROUP_INET4_BIND:        "BPF_CGROUP_INET4_BIND",
	BPF_CGROUP_INET6_BIND:        "BPF_CGROUP_INET6_BIND",
	BPF_CGROUP_INET4_CONNECT:     "BPF_CGROUP_INET4_CONNECT",
	BPF_CGROUP_INET6_CONNECT:     "BPF_CGROUP_INET6_CONNECT",
	BPF_CGROUP_INET4_POST_BIND:   "BPF_CGROUP_INET4_POST_BIND",
	BPF_CGROUP_INET6_POST_BIND:   "BPF_CGROUP_INET6_POST_BIND",
	BPF_CGROUP_UDP4_SENDMSG:      "BPF_CGROUP_UDP4_SENDMSG",
	BPF_CGROUP_UDP6_SENDMSG:      "BPF_CGROUP_UDP6_SENDMSG",
	BPF_LIRC_MODE2:               "BPF_LIRC_MODE2",
	BPF_FLOW_DISSECTOR:           "BPF_FLOW_DISSECTOR",
	BPF_CGROUP_SYSCTL:            "BPF_CGROUP_SYSCTL",
	BPF_CGROUP_UDP4_RECVMSG:      "BPF_CGROUP_UDP4_RECVMSG",
	BPF_CGROUP_UDP6_RECVMSG:      "BPF_CGROUP_UDP6_RECVMSG",
	BPF_CGROUP_GETSOCKOPT:        "BPF_CGROUP_GETSOCKOPT",
	BPF_CGROUP_SETSOCKOPT:        "BPF_CGROUP_SETSOCKOPT",
	BPF_TRACE_RAW_TP:             "BPF_TRACE_RAW_TP",
	BPF_TRACE_FENTRY:             "BPF_TRACE_FENTRY",
	BPF_TRACE_FEXIT:              "BPF_TRACE_FEXIT",
	BPF_MODIFY_RETURN:            "BPF_MODIFY_RETURN",
	BPF_LSM_MAC:                  "BPF_LSM_MAC",
	BPF_TRACE_ITER:               "BPF_TRACE_ITER",
	BPF_CGROUP_INET4_GETPEERNAME: "BPF_CGROUP_INET4_GETPEERNAME",
	BPF_CGROUP_INET6_GETPEERNAME: "BPF_CGROUP_INET6_GETPEERNAME",
	BPF_CGROUP_INET4_GETSOCKNAME: "BPF_CGROUP_INET4_GETSOCKNAME",
	BPF_CGROUP_INET6_GETSOCKNAME: "BPF_CGROUP_INET6_GETSOCKNAME",
	BPF_XDP_DEVMAP:               "BPF_XDP_DEVMAP",
	BPF_CGROUP_INET_SOCK_RELEASE: "BPF_CGROUP_INET_SOCK_RELEASE",
	BPF_XDP_CPUMAP:               "BPF_XDP_CPUMAP",
	BPF_SK_LOOKUP:                "BPF_SK_LOOKUP",
	BPF_XDP:                      "BPF_XDP",
}

func (at BPFAttachType) String() string {
	str := bpfAttachTypeToStr[at]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

// From bpf_link_type https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L255
type BPFLinkType uint32

const (
	BPF_LINK_TYPE_UNSPEC         BPFLinkType = 0
	BPF_LINK_TYPE_RAW_TRACEPOINT BPFLinkType = 1
	BPF_LINK_TYPE_TRACING        BPFLinkType = 2
	BPF_LINK_TYPE_CGROUP         BPFLinkType = 3
	BPF_LINK_TYPE_ITER           BPFLinkType = 4
	BPF_LINK_TYPE_NETNS          BPFLinkType = 5
	BPF_LINK_TYPE_XDP            BPFLinkType = 6
)

var bpfLinkTypeToStr = map[BPFLinkType]string{
	BPF_LINK_TYPE_UNSPEC:         "BPF_LINK_TYPE_UNSPEC",
	BPF_LINK_TYPE_RAW_TRACEPOINT: "BPF_LINK_TYPE_RAW_TRACEPOINT",
	BPF_LINK_TYPE_TRACING:        "BPF_LINK_TYPE_TRACING",
	BPF_LINK_TYPE_CGROUP:         "BPF_LINK_TYPE_CGROUP",
	BPF_LINK_TYPE_ITER:           "BPF_LINK_TYPE_ITER",
	BPF_LINK_TYPE_NETNS:          "BPF_LINK_TYPE_NETNS",
	BPF_LINK_TYPE_XDP:            "BPF_LINK_TYPE_XDP",
}

func (lt BPFLinkType) String() string {
	str := bpfLinkTypeToStr[lt]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

type BPFTaskFDType uint32

const (
	BPF_FD_TYPE_RAW_TRACEPOINT BPFTaskFDType = iota
	BPF_FD_TYPE_TRACEPOINT
	BPF_FD_TYPE_KPROBE
	BPF_FD_TYPE_KRETPROBE
	BPF_FD_TYPE_UPROBE
	BPF_FD_TYPE_URETPROBE
)

var bpfTaskFDTypeToStr = map[BPFTaskFDType]string{
	BPF_FD_TYPE_RAW_TRACEPOINT: "BPF_FD_TYPE_RAW_TRACEPOINT",
	BPF_FD_TYPE_TRACEPOINT:     "BPF_FD_TYPE_TRACEPOINT",
	BPF_FD_TYPE_KPROBE:         "BPF_FD_TYPE_KPROBE",
	BPF_FD_TYPE_KRETPROBE:      "BPF_FD_TYPE_KRETPROBE",
	BPF_FD_TYPE_UPROBE:         "BPF_FD_TYPE_UPROBE",
	BPF_FD_TYPE_URETPROBE:      "BPF_FD_TYPE_URETPROBE",
}

func (ft BPFTaskFDType) String() string {
	str := bpfTaskFDTypeToStr[ft]
	if str == "" {
		return "UNKNOWN"
	}

	return str
}

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
type BPFProgAttachFlags uint32

const (
	BPFProgAttachAllowOverride BPFProgAttachFlags = 1 << iota
	BPFProgAttachAllowMulti
	BPFProgAttachReplace
)

// The verifier log level
// https://github.com/torvalds/linux/blob/master/include/linux/bpf_verifier.h#L360
type BPFLogLevel uint32

const (
	BPFLogLevelDisabled BPFLogLevel = iota
	BPFLogLevelBasic
	BPFLogLevelVerbose
)

type BPFProgLoadFlags uint32

const (
	/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
	* verifier will perform strict alignment checking as if the kernel
	* has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
	* and NET_IP_ALIGN defined to 2.
	 */
	BPFProgLoadStrictAlignment BPFProgLoadFlags = 1 << iota

	/* If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
	 * verifier will allow any alignment whatsoever.  On platforms
	 * with strict alignment requirements for loads ands stores (such
	 * as sparc and mips) the verifier validates that all loads and
	 * stores provably follow this requirement.  This flag turns that
	 * checking and enforcement off.
	 *
	 * It is mostly used for testing when we want to validate the
	 * context and memory access aspects of the verifier, but because
	 * of an unaligned access the alignment check would trigger before
	 * the one we are interested in.
	 */
	BPFProgLoadAnyAlignment

	/* BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
	 * Verifier does sub-register def/use analysis and identifies instructions whose
	 * def only matters for low 32-bit, high 32-bit is never referenced later
	 * through implicit zero extension. Therefore verifier notifies JIT back-ends
	 * that it is safe to ignore clearing high 32-bit for these instructions. This
	 * saves some back-ends a lot of code-gen. However such optimization is not
	 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
	 * hence hasn't used verifier's analysis result. But, we really want to have a
	 * way to be able to verify the correctness of the described optimization on
	 * x86_64 on which testsuites are frequently exercised.
	 *
	 * So, this flag is introduced. Once it is set, verifier will randomize high
	 * 32-bit for those instructions who has been identified as safe to ignore them.
	 * Then, if verifier is not doing correct analysis, such randomization will
	 * regress tests to expose bugs.
	 */
	BPFProgLoadTestRndHI32

	/* The verifier internal test flag. Behavior is undefined */
	BPFProgLoadTestStateFreq

	/* If BPF_F_SLEEPABLE is used in BPF_PROG_LOAD command, the verifier will
	 * restrict map and helper usage for such programs. Sleepable BPF programs can
	 * only be attached to hooks where kernel execution context allows sleeping.
	 * Such programs are allowed to use helpers that may sleep like
	 * bpf_copy_from_user().
	 */
	BPFProgLoadSleepable
)

const BPF_TAG_SIZE = 8

var BPFProgInfoSize = int(unsafe.Sizeof(BPFProgInfo{}))

// BPFProgInfo is the structure used by the kernel to communicate program information back to
// userspace when calling the BPF_OBJ_GET_INFO_BY_FD command with a program file descriptor.
// Based on https://github.com/torvalds/linux/blob/e49d033bddf5b565044e2abe4241353959bc9120/include/uapi/linux/bpf.h#L4548
type BPFProgInfo struct {
	Type                 BPFProgType
	ID                   uint32
	Tag                  [BPF_TAG_SIZE]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uintptr
	XlatedProgInsns      uintptr
	LoadTime             uint64
	CreatedByUID         uint32
	NumMapIDs            uint32
	MapIDs               uintptr
	Name                 [BPF_OBJ_NAME_LEN]byte
	IfIndex              uint32
	Flags                BPFProgInfoFlags
	NetNSDev             uint64
	NetNSIno             uint64
	NumJitedKSyms        uint32
	NumJitedFuncLens     uint32
	JitedKsyms           uintptr
	JitedFuncLens        uintptr
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uintptr
	NumFuncInfo          uint32
	NumLineInfo          uint32
	LineInfo             uintptr
	JitedLineInfo        uintptr
	NumJitedLineInfo     uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NumProgTags          uint32
	ProgTags             uintptr
	RunTimeNs            uint64
	RunCnt               uint64
	RecursionMisses      uint64
}

// A alignment hole was used for additional flags, since the comment says
// this value may contain extra flags in the future this custom type was created.
// This will hopefully allow for more compatibility
// https://github.com/torvalds/linux/commit/b85fab0e67b162014cd328cb4e2a8e8ae382cb8a
// TODO make getter/setter for every flag (GPLCompatible)
type BPFProgInfoFlags uint32

var BPFMapInfoSize = int(unsafe.Sizeof(BPFMapInfo{}))

type BPFMapInfo struct {
	Type       BPFMapType
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       [BPF_OBJ_NAME_LEN]byte
	IfIndex    uint32
	NetNSDev   uint64
	NetNSIno   uint64
}

type BPFFuncInfo struct {
	InstructionOffset uint32
	TypeID            uint32
}

type BPFLineInfo struct {
	InstructionOffset uint32
	FileNameOffset    uint32
	LineOffset        uint32
	ColumnOffset      uint32
}
