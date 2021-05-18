package bpfsys

import (
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpftypes"
)

type BPFAttribute interface {
	ToPtr() unsafe.Pointer
	Size() uintptr
}

// BPFAttrMapCreate is the attribute for the BPF_MAP_CREATE command
type BPFAttrMapCreate struct {
	MapType               bpftypes.BPFMapType  // one of enum bpf_map_type
	KeySize               uint32               // size of key in bytes
	ValueSize             uint32               // size of value in bytes
	MaxEntries            uint32               // max number of entries in a map
	MapFlags              bpftypes.BPFMapFlags // BPF_MAP_CREATE related flags
	InnerMapFD            BPFfd                // fd pointing to the inner map
	NumaNode              uint32               // numa node (effective only if BPF_F_NUMA_NODE is set)
	MapName               [bpftypes.BPF_OBJ_NAME_LEN]byte
	MapIFIndex            uint32 // ifindex of netdev to create on
	BTFFD                 BPFfd  // fd pointing to a BTF type data
	BTFKeyTypeID          uint32 // BTF type_id of the key
	BTFValueTypeID        uint32 // BTF type_id of the value
	BTFVMLinuxValueTypeID uint32 // BTF type_id of a kernel-struct stored as the map value
}

func (amc *BPFAttrMapCreate) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(amc)
}

func (amc *BPFAttrMapCreate) Size() uintptr {
	return unsafe.Sizeof(*amc)
}

// BPFAttrMapElem is used as attribute for the BPF_MAP_*_ELEM commands
type BPFAttrMapElem struct {
	MapFD BPFfd
	Key   uintptr // Pointer to the key value
	// In the kernel this is a union, so depending on context this field is pointer to "Value" or "NextKey"
	Value_NextKey uintptr
	Flags         BPFAttrMapElemFlags
}

func (ame *BPFAttrMapElem) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(ame)
}

func (ame *BPFAttrMapElem) Size() uintptr {
	return unsafe.Sizeof(*ame)
}

// BPFAttrMapElemFlags should be one of the following:
//  * BPFMapElemAny
//  * BPFMapElemNoExists
//  * BPFMapElemExists
//  * BPFMapElemLock
type BPFAttrMapElemFlags uint64

const (
	// BPFMapElemAny Create new elements or update a existing elements.
	BPFMapElemAny BPFAttrMapElemFlags = iota
	// BPFMapElemNoExists Create new elements only if they do not exist.
	BPFMapElemNoExists
	// BPFMapElemExists Update existing elements.
	BPFMapElemExists
	// BPFMapElemLock Update spin_lock-ed map elements. This must be
	// specified if the map value contains a spinlock.
	BPFMapElemLock
)

// BPFAttrMapBatch is used as attribute for the BPF_MAP_*_BATCH commands
type BPFAttrMapBatch struct {
	InBatch   uintptr // start batch, NULL to start from beginning
	OutBatch  uintptr // output: next start batch
	Keys      uintptr
	Values    uintptr
	Count     uint32 // input/output:  input: # of key/value elements, output: # of filled elements
	MapFD     BPFfd
	ElemFlags BPFAttrMapElemFlags
	Flags     BPFAttrMapElemFlags
}

func (amb *BPFAttrMapBatch) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(amb)
}

func (amb *BPFAttrMapBatch) Size() uintptr {
	return unsafe.Sizeof(*amb)
}

type BPFAttrProgramLoad struct {
	ProgramType   bpftypes.BPFProgType // one of enum bpf_prog_type
	InsnCnt       uint32               // the amount of bpf instruction in program
	Insns         uintptr              // pointer to the bpf instructions
	License       uintptr              // Pointer to string containing the license
	LogLevel      bpftypes.BPFLogLevel // verbosity level of verifier
	LogSize       uint32               // size of user buffer
	LogBuf        uintptr              // pointer to buffer where verifier log will be written to
	KernelVersion uint32               // not used
	ProgFlags     bpftypes.BPFProgLoadFlags
	ProgName      [bpftypes.BPF_OBJ_NAME_LEN]byte
	ProgIFIndex   uint32 // ifindex of netdev to prep for

	// For some prog types expected attach type must be known at
	// load time to verify attach type specific parts of prog
	// (context accesses, allowed helpers, etc).
	ExpectedAttachType bpftypes.BPFAttachType

	// TODO uncomment fields when we are ready to add BTF support https://www.kernel.org/doc/html/latest/bpf/btf.html

	// ProgBTFFD                   uint32  // fd pointing to BTF type data
	// FuncInfoRecSize             uint32  // userspace bpf_func_info size
	// FuncInfo                    uintptr // func info
	// FuncInfoCnt                 uint32  // number of bpf_func_info records
	// LineInfoRecSize             uint32  // userspace bpf_line_info size
	// LineInfo                    uint64  // line info
	// LineInfoCnt                 uint32  // number of bpf_line_info records
	// AttachBTFID                 uint32  // in-kernel BTF type id to attach to
	// valid prog_fd to attach to bpf prog or valid module BTF object fd or 0 to attach to vmlinux
	// AttachProgFD_AttachBTFObjFD uint32
}

func (amb *BPFAttrProgramLoad) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(amb)
}

func (amb *BPFAttrProgramLoad) Size() uintptr {
	return unsafe.Sizeof(*amb)
}

// BPFAttrObj is used as attribute in the BPF_OBJ_* commands
type BPFAttrObj struct {
	Pathname  uintptr // pointer to cstring
	BPFfd     BPFfd
	FileFlags uint32
}

func (ao *BPFAttrObj) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(ao)
}

func (ao *BPFAttrObj) Size() uintptr {
	return unsafe.Sizeof(*ao)
}

// BPFAttrProgAttachDetach is used as attribute in the BPF_PROG_ATTACH/DETACH commands
type BPFAttrProgAttachDetach struct {
	TargetFD     uint32 // container object to attach to
	AttachBPFFD  BPFfd  // eBPF program to attach
	AttachType   bpftypes.BPFAttachType
	AttachFlags  bpftypes.BPFProgAttachFlags
	ReplaceBPFFD BPFfd // previously attached eBPF program to replace if BPF_F_REPLACE is used
}

func (apa *BPFAttrProgAttachDetach) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(apa)
}

func (apa *BPFAttrProgAttachDetach) Size() uintptr {
	return unsafe.Sizeof(*apa)
}

// BPFAttrProgTestRun is the attribute for the BPF_PROG_TEST_RUN command
type BPFAttrProgTestRun struct {
	ProgFD      BPFfd
	Retval      uint32
	DataSizeIn  uint32  // Size of the input data buffer
	DataSizeOut uint32  // Size of the output data buffer
	DataIn      uintptr // Pointer to a buffer with input data
	DataOut     uintptr // Pointer to a buffer with output data
	Repeat      uint32
	Duration    uint32
	CtxSizeIn   uint32  // Size of the input ctx
	CtxSizeOut  uint32  // Size of the output ctx
	CtxIn       uintptr // Pointer to the input ctx
	CtxOut      uintptr // Pointer to the output ctx
	Flags       uint32
	CPU         uint32
}

func (apt *BPFAttrProgTestRun) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(apt)
}

func (apt *BPFAttrProgTestRun) Size() uintptr {
	return unsafe.Sizeof(*apt)
}

// BPFAttrGetID is used as attribute in the BPF_*_GET_*_ID commands
type BPFAttrGetID struct {
	ID        uint32
	NextID    uint32
	OpenFlags uint32
}

func (agi *BPFAttrGetID) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(agi)
}

func (agi *BPFAttrGetID) Size() uintptr {
	return unsafe.Sizeof(*agi)
}

// BPFAttrGetInfoFD is used as attribute in the BPF_OBJ_GET_INFO_BY_FD command
type BPFAttrGetInfoFD struct {
	BPFFD   BPFfd
	InfoLen uint32  // Length of the info buffer
	Info    uintptr // Pointer to buffer where the kernel will store info
}

func (agi *BPFAttrGetInfoFD) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(agi)
}

func (agi *BPFAttrGetInfoFD) Size() uintptr {
	return unsafe.Sizeof(*agi)
}

// BPFAttrProgQuery is used as attribute in the BPF_PROG_QUERY command
type BPFAttrProgQuery struct {
	TargetFD    uint32
	AttachType  bpftypes.BPFAttachType
	QueryFlags  BPFAttrProgQueryFlags
	AttachFlags uint32
	ProgIDs     uintptr // Pointer to buffer where ids will be stored
	ProgCnt     uint32
}

type BPFAttrProgQueryFlags uint32

const (
	// ProgQueryQueryEffective Query effective (directly attached + inherited from ancestor cgroups)
	// programs that will be executed for events within a cgroup.
	// attach_flags with this flag are returned only for directly attached programs.
	ProgQueryQueryEffective BPFAttrProgQueryFlags = 1 << 0
)

func (apq *BPFAttrProgQuery) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(apq)
}

func (apq *BPFAttrProgQuery) Size() uintptr {
	return unsafe.Sizeof(*apq)
}

// BPFAttrRawTracepointOpen is used as attribute in the BPF_RAW_TRACEPOINT_OPEN command
type BPFAttrRawTracepointOpen struct {
	Name   uintptr
	ProgFD BPFfd
}

func (art *BPFAttrRawTracepointOpen) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(art)
}

func (art *BPFAttrRawTracepointOpen) Size() uintptr {
	return unsafe.Sizeof(*art)
}

// BPFAttrBTFLoad is the attribute for the BPF_BTF_LOAD command
type BPFAttrBTFLoad struct {
	BTF         uintptr
	BTFLogBuf   uintptr
	BTFSize     uint32
	BTFLogSize  uint32
	BTFLogLevel uint32
}

func (abl *BPFAttrBTFLoad) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(abl)
}

func (abl *BPFAttrBTFLoad) Size() uintptr {
	return unsafe.Sizeof(*abl)
}

type BPFAttrTaskFDQuery struct {
	PID         uint32
	FD          BPFfd
	Flags       uint32
	BufLen      uint32
	Buf         uintptr
	ProgID      uint32
	FDType      bpftypes.BPFTaskFDType
	ProbeOffset uint64
	ProbeAddr   uint64
}

func (atq *BPFAttrTaskFDQuery) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(atq)
}

func (atq *BPFAttrTaskFDQuery) Size() uintptr {
	return unsafe.Sizeof(*atq)
}

// BPFAttrLinkCreate is used by BPF_LINK_CREATE command
type BPFAttrLinkCreate struct {
	ProgFD                 BPFfd
	TargetFD_TargetIFIndex uint32
	AttachType             bpftypes.BPFAttachType
	Flags                  uint32

	// TODO create a type to represent
	// 		union {
	// 			__u32		target_btf_id;	/* btf_id of target to attach to */
	// 			struct {
	// 				__aligned_u64	iter_info;	/* extra bpf_iter_link_info */
	// 				__u32		iter_info_len;	/* iter_info length */
	// 			};
	// 		};
}

func (alc *BPFAttrLinkCreate) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(alc)
}

func (alc *BPFAttrLinkCreate) Size() uintptr {
	return unsafe.Sizeof(*alc)
}

// BPFAttrLinkUpdate is used by BPF_LINK_UPDATE command
type BPFAttrLinkUpdate struct {
	LinkFD    uint32
	NewProgFD BPFfd
	Flags     uint32
	OldProgFD BPFfd
}

func (alu *BPFAttrLinkUpdate) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(alu)
}

func (alu *BPFAttrLinkUpdate) Size() uintptr {
	return unsafe.Sizeof(*alu)
}

type BPFAttrLinkDetach struct {
	LinkID uint32
}

func (ald *BPFAttrLinkDetach) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(ald)
}

func (ald *BPFAttrLinkDetach) Size() uintptr {
	return unsafe.Sizeof(*ald)
}

// BPFAttrEnableStats is used by BPF_ENABLE_STATS command
type BPFAttrEnableStats struct {
	Type uint32
}

func (aes *BPFAttrEnableStats) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(aes)
}

func (aes *BPFAttrEnableStats) Size() uintptr {
	return unsafe.Sizeof(*aes)
}

// BPFAttrIterCreate is used by BPF_ITER_CREATE command
type BPFAttrIterCreate struct {
	LinkFD uint32
	Flags  uint32
}

func (aic *BPFAttrIterCreate) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(aic)
}

func (aic *BPFAttrIterCreate) Size() uintptr {
	return unsafe.Sizeof(*aic)
}

// BPFAttrProgBindMap is uses as attribute for the BPF_PROG_BIND_MAP command
type BPFAttrProgBindMap struct {
	ProgID uint32
	MapFD  BPFfd
	Flags  uint32
}

func (abm *BPFAttrProgBindMap) ToPtr() unsafe.Pointer {
	return unsafe.Pointer(abm)
}

func (abm *BPFAttrProgBindMap) Size() uintptr {
	return unsafe.Sizeof(*abm)
}
