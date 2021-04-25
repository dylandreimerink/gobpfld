package bpfsys

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

// ENOTSUPP - Operation is not supported
var ENOTSUPP = syscall.Errno(524)

// a map of string translations for syscall errors which are no included in the standard library
var nonStdErrors = map[syscall.Errno]string{
	ENOTSUPP: "Operation is not supported",
}

// ErrNotSupported is returned when attempting to use a feature that is not supported
// by the kernel version on which the program is executed.
var ErrNotSupported = errors.New("feature not supported by kernel version")

type BPFSyscallError struct {
	// The underlaying syscall error number
	Errno syscall.Errno
	// Context specific error information since the same code can have different
	// meaning depending on context
	Err string
}

func (e *BPFSyscallError) Error() string {
	errStr := nonStdErrors[e.Errno]
	if errStr == "" {
		errStr = e.Errno.Error()
	}

	if e.Err == "" {
		return fmt.Sprintf("%s (%d)", errStr, e.Errno)
	}

	return fmt.Sprintf("%s (%s)(%d)", e.Err, errStr, e.Errno)
}

// BPFfd is an alias of a file descriptor returned by bpf to identify a map or program.
// Since not all the usual file descriptor functions are available to these types of fds.
//
// eBPF objects (maps and programs) can be shared between processes.
//  * After **fork**\ (2), the child inherits file descriptors
//    referring to the same eBPF objects.
//  * File descriptors referring to eBPF objects can be transferred over
//    **unix**\ (7) domain sockets.
//  * File descriptors referring to eBPF objects can be duplicated in the
//    usual way, using **dup**\ (2) and similar calls.
//  * File descriptors referring to eBPF objects can be pinned to the
//    filesystem using the **BPF_OBJ_PIN** command of **bpf**\ (2).
//
// An eBPF object is deallocated only after all file descriptors referring
// to the object have been closed and no references remain pinned to the
// filesystem or attached (for example, bound to a program or device).
type BPFfd uint32

// Close closes a file descriptor
func (fd BPFfd) Close() error {
	_, _, errno := syscall.Syscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
	if errno != 0 {
		return &BPFSyscallError{
			Errno: errno,
			Err: map[syscall.Errno]string{
				syscall.EBADF: "fd isn't a valid open file descriptor",
				syscall.EINTR: "The Close() call was interrupted by a signal; see signal(7)",
				syscall.EIO:   "An I/O error occurred",
			}[errno],
		}
	}

	return nil
}

// Bpf is a wrapper around the BPF syscall, so a very low level function.
// It is not recommended to use it directly unless you know what you are doing
func Bpf(cmd bpftypes.BPFCommand, attr BPFAttribute, size int) (fd BPFfd, err error) {
	r0, _, errno := syscall.Syscall(SYS_BPF, uintptr(cmd), uintptr(attr.ToPtr()), uintptr(size))
	if errno != 0 {
		err = &BPFSyscallError{
			Errno: errno,
		}
	}

	return BPFfd(r0), err
}

// Wraps Bpf but discards the first return value
func bpfNoReturn(cmd bpftypes.BPFCommand, attr BPFAttribute, size int) error {
	_, err := Bpf(cmd, attr, size)
	return err
}

// MapCreate creates a map and return a file descriptor that refers to the
// map. The close-on-exec file descriptor flag (see fcntl(2) in linux man pages)
// is automatically enabled for the new file descriptor.
//
// Calling Close on the returned file descriptor will delete the map.
func MapCreate(attr *BPFAttrMapCreate) (fd BPFfd, err error) {
	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapNumaCreate) {
		if attr.NumaNode != uint32(0) || attr.MapFlags&bpftypes.BPFMapFlagsNUMANode > 0 {
			return 0, fmt.Errorf("NUMA node can't be specified: %w", ErrNotSupported)
		}
	}

	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapSyscallRW) {
		if attr.MapFlags&(bpftypes.BPFMapFlagsReadOnly|bpftypes.BPFMapFlagsWriteOnly) > 0 {
			return 0, fmt.Errorf("map access can't be restricted from syscall side: %w", ErrNotSupported)
		}
	}

	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapName) {
		if attr.MapName != [16]byte{} {
			return 0, fmt.Errorf("map name can't be specified: %w", ErrNotSupported)
		}
	}

	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapZeroSeed) {
		if attr.MapFlags&bpftypes.BPFMapFlagsZeroSeed > 0 {
			return 0, fmt.Errorf("zero seed flag not supported: %w", ErrNotSupported)
		}
	}

	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBPFRW) {
		if attr.MapFlags&(bpftypes.BPFMapFlagsReadOnlyProg|bpftypes.BPFMapFlagsWriteOnlyProg) > 0 {
			return 0, fmt.Errorf("map access can't be restricted from bpf side: %w", ErrNotSupported)
		}
	}

	return Bpf(bpftypes.BPF_MAP_CREATE, attr, int(attr.Size()))
}

// MapLookupElem looks up an element with a given 'Key' in the map referred to by the file descriptor 'MapFD'.
// Key must be a pointer to the key value, Value_NextKey must be a pointer to a value which the kernel will overwrite
// with the value in the map.
// For this call, only a 'Flags' value of 0 or BPFMapElemLock is allowed
func MapLookupElem(attr *BPFAttrMapElem) error {
	return bpfNoReturn(bpftypes.BPF_MAP_LOOKUP_ELEM, attr, int(attr.Size()))
}

// MapUpdateElem creates or update an element (key/value pair) in a specified map.
func MapUpdateElem(attr *BPFAttrMapElem) error {
	err := bpfNoReturn(bpftypes.BPF_MAP_UPDATE_ELEM, attr, int(attr.Size()))
	if syserr, ok := err.(*BPFSyscallError); ok {
		syserr.Err = map[syscall.Errno]string{
			syscall.E2BIG:  "The number of elements in the map reached the *max_entries* limit specified at map creation time.",
			syscall.EEXIST: "attr.Flags specifies BPFMapElemNoExists and the element with attr.Key already exists in the map.",
			syscall.ENOENT: "attr.Flags specifies BPFMapElemExists and the element with attr.Key does not exist in the map",
		}[syserr.Errno]
		return syserr
	}
	return err
}

// MapDeleteElem looks up and delete an element by key in a specified map.
func MapDeleteElem(attr *BPFAttrMapElem) error {
	return bpfNoReturn(bpftypes.BPF_MAP_DELETE_ELEM, attr, int(attr.Size()))
}

// MapGetNextKey looks up an element by attr.Key in a specified map and sets the key
// of the key of the next element in attr.Value_NextValue. Can be used to iterate over all elements
//
// The following cases can be used to iterate over all elements of the map:
//  * If attr.Key is not found, the operation sets the
//    attr.Value_NextValue pointer to the key of the first element.
//  * If attr.Key is found, the operation returns sets the
//    attr.Value_NextValue pointer to the key of the next element.
//  * If attr.Key is the last element, an error with errno ENOENT(2) is returned.
func MapGetNextKey(attr *BPFAttrMapElem) error {
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapGetNextNull) &&
		attr.Value_NextKey == uintptr(0) {

		return fmt.Errorf("NextKey == NULL: %w", ErrNotSupported)
	}

	err := bpfNoReturn(bpftypes.BPF_MAP_GET_NEXT_KEY, attr, int(attr.Size()))
	if syserr, ok := err.(*BPFSyscallError); ok {
		syserr.Err = map[syscall.Errno]string{
			syscall.ENOENT: "element indicated by attr.Key is the last in the map",
		}[syserr.Errno]
		return syserr
	}
	return err
}

// LoadProgram verifies and loads an eBPF program, returning a new file descriptor associated with the program.
// The close-on-exec file descriptor flag (see fcntl(2) in linux man pages) is automatically enabled for
// the new file descriptor.
//
// Calling Close on the returned file descriptor will unload the program.
func LoadProgram(attr *BPFAttrProgramLoad) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_PROG_LOAD, attr, int(attr.Size()))
}

// ObjectPin pins an eBPF program or map referred by the specified attr.BPFfd
// to the provided attr.Pathname on the filesystem.
//
// attr.Pathname must not contain a dot (".").
//
// On success, attr.Pathname retains a reference to the eBPF object,
// preventing deallocation of the object when the original
// attr.BPFfd is closed. This allow the eBPF object to live beyond
// attr.BPFfd.Close(), and hence the lifetime of the parent
// process.
//
// Applying syscall.Unlink or similar calls to the attr.Pathname
// unpins the object from the filesystem, removing the reference.
// If no other file descriptors or filesystem nodes refer to the
// same object, it will be deallocated.
//
// The filesystem type for the parent directory of attr.Pathname must
// be **BPF_FS_MAGIC**. On most systems the /sys/fs/bpf is a BPF_FS_MAGIC directory
func ObjectPin(attr *BPFAttrObj) error {
	return bpfNoReturn(bpftypes.BPF_OBJ_PIN, attr, int(attr.Size()))
}

// ObjectGet opens a file descriptor for the eBPF object pinned to the specified attr.Pathname
func ObjectGet(attr *BPFAttrObj) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_OBJ_GET, attr, int(attr.Size()))
}

// ProgramAttach attaches an eBPF program to a attr.TargetFD at the specified attr.AttachType hook.
// The attr.AttachType specifies the eBPF attachment point to attach the program to,
//  and must be one of bpftypes.BPFAttachType.
// The attr.AttachBPFFD must be a valid file descriptor for a loaded eBPF program of a cgroup, flow dissector, LIRC,
//  sockmap or sock_ops type corresponding to the specified attr.AttachType.
//
// 	The attr.TargetFD must be a valid file descriptor for a kernel
// 	object which depends on the attach type of attr.AttachBPFFD:
// 	bpftypes.BPF_PROG_TYPE_CGROUP_DEVICE,
// 	bpftypes.BPF_PROG_TYPE_CGROUP_SKB,
// 	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK,
// 	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
// 	bpftypes.BPF_PROG_TYPE_CGROUP_SOCKOPT,
// 	bpftypes.BPF_PROG_TYPE_CGROUP_SYSCTL,
// 	bpftypes.BPF_PROG_TYPE_SOCK_OPS
// 		Control Group v2 hierarchy with the eBPF controller
// 		enabled. Requires the kernel to be compiled with
// 		CONFIG_CGROUP_BPF.
// 	bpftypes.BPF_PROG_TYPE_FLOW_DISSECTOR
// 		Network namespace (eg /proc/self/ns/net).
// 	bpftypes.BPF_PROG_TYPE_LIRC_MODE2
// 		LIRC device path (eg /dev/lircN). Requires the kernel
// 		to be compiled with CONFIG_BPF_LIRC_MODE2.
// 	bpftypes.BPF_PROG_TYPE_SK_SKB,
// 	bpftypes.BPF_PROG_TYPE_SK_MSG
// 		eBPF map of socket type (eg bpftypes.BPF_MAP_TYPE_SOCKHASH).
func ProgramAttach(attr *BPFAttrProgAttachDetach) error {
	return bpfNoReturn(bpftypes.BPF_PROG_ATTACH, attr, int(attr.Size()))
}

// ProgramDetach detaches the eBPF program associated with the attr.TargetFD at the hook specified by *attach_type*.
// The program must have been previously attached using ProgramAttach.
func ProgramDetach(attr *BPFAttrProgAttachDetach) error {
	return bpfNoReturn(bpftypes.BPF_PROG_DETACH, attr, int(attr.Size()))
}

// ProgramTestRun runs the eBPF program associated with the attr.ProgFD a attr.Repeat number of times against
// a provided program context attr.CtxIn and data attr.DataIn, and return the modified program context attr.CtxOut,
// attr.DataOut (for example, packet data), result of the execution attr.Retval, and attr.Duration of the test run.
func ProgramTestRun(attr *BPFAttrProgTestRun) error {
	err := bpfNoReturn(bpftypes.BPF_PROG_TEST_RUN, attr, int(attr.Size()))
	if syserr, ok := err.(*BPFSyscallError); ok {
		syserr.Err = map[syscall.Errno]string{
			syscall.ENOSPC: "Either attr.DataSizeOut or attr.CtxSizeOut is too small",
			ENOTSUPP:       "This command is not supported by the program type of the program referred to by attr.ProgFD",
		}[syserr.Errno]
		return syserr
	}

	return err
}

// ProgramGetNextID fetches the next eBPF program currently loaded into the kernel.
// Looks for the eBPF program with an id greater than attr.ID and updates attr.NextID on success.
// If no other eBPF programs remain with ids higher than attr.ID, an error with errno ENOENT(2) is returned.
func ProgramGetNextID(attr *BPFAttrGetID) error {
	return bpfNoReturn(bpftypes.BPF_PROG_GET_NEXT_ID, attr, int(attr.Size()))
}

// MapGetNextID fetches the next eBPF map currently loaded into the kernel.
// Looks for the eBPF map with an id greater than attr.ID and updates attr.NextID on success.
// If no other eBPF maps remain with ids higher than attr.ID, an error with errno ENOENT(2) is returned.
func MapGetNextID(attr *BPFAttrGetID) error {
	return bpfNoReturn(bpftypes.BPF_MAP_GET_NEXT_ID, attr, int(attr.Size()))
}

// ProgramGetFDByID opens a file descriptor for the eBPF program corresponding to attr.ID.
func ProgramGetFDByID(attr *BPFAttrGetID) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_PROG_GET_FD_BY_ID, attr, int(attr.Size()))
}

// MapGetFDByID queries the kernel for the file descriptor of a map with the given ID.
// If successful the syscall will return the file descriptor as the first return value
func MapGetFDByID(attr *BPFAttrGetID) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_MAP_GET_FD_BY_ID, attr, int(attr.Size()))
}

// ObjectGetInfoByFD obtains information about the eBPF object corresponding to attr.BPFFD.
// Populates up to attr.InfoLen bytes of attr.Info, which will be in one of the following
// formats depending on the eBPF object type of attr.BPFFD:
//  * bpftypes.BPFProgInfo
//  * bpftypes.BPFMapInfo
//  * struct bpf_btf_info (TODO make go version of struct in bpftypes)
//  * struct bpf_link_info (TODO make go version of struct in bpftypes)
func ObjectGetInfoByFD(attr *BPFAttrGetInfoFD) error {
	_, errno := Bpf(bpftypes.BPF_OBJ_GET_INFO_BY_FD, attr, int(attr.Size()))
	return errno
}

// ProgramQuery obtains information about eBPF programs associated with the specified attr.AttachType hook.
// The attr.TargetFD must be a valid file descriptor for a kernel object which depends on
// the attach type of attr.AttachType:
//	bpftypes.BPF_PROG_TYPE_CGROUP_DEVICE,
//	bpftypes.BPF_PROG_TYPE_CGROUP_SKB,
//	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK,
//	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
//	bpftypes.BPF_PROG_TYPE_CGROUP_SOCKOPT,
//	bpftypes.BPF_PROG_TYPE_CGROUP_SYSCTL,
//	bpftypes.BPF_PROG_TYPE_SOCK_OPS
//		Control Group v2 hierarchy with the eBPF controller
//		enabled. Requires the kernel to be compiled with
//		CONFIG_CGROUP_BPF.
//	bpftypes.BPF_PROG_TYPE_FLOW_DISSECTOR
//		Network namespace (eg /proc/self/ns/net).
//	bpftypes.BPF_PROG_TYPE_LIRC_MODE2
//		LIRC device path (eg /dev/lircN). Requires the kernel
//		to be compiled with CONFIG_BPF_LIRC_MODE2.
//
//	ProgramQuery always fetches the number of programs
//	attached and the attr.AttachFlags which were used to attach those
//	programs. Additionally, if attr.ProgIDs is nonzero and the number
//	of attached programs is less than attr.ProgCnt, populates
//	attr.ProgIDs with the eBPF program ids of the programs attached
//	at attr.TargetFD.
//
//	The following flags may alter the result:
//
//	ProgQueryQueryEffective
//		Only return information regarding programs which are
//		currently effective at the specified attr.TargetFD.
func ProgramQuery(attr *BPFAttrProgQuery) error {
	return bpfNoReturn(bpftypes.BPF_PROG_QUERY, attr, int(attr.Size()))
}

// RawTracepointOpen attaches an eBPF program to a tracepoint *name* to access kernel
// internal arguments of the tracepoint in their raw form.
//
// The attr.ProgID must be a valid file descriptor associated with
// a loaded eBPF program of type bpftypes.BPF_PROG_TYPE_RAW_TRACEPOINT.
//
// No ABI guarantees are made about the content of tracepoint
// arguments exposed to the corresponding eBPF program.
//
// Applying Close to the file descriptor returned by
// RawTracepointOpen will delete the map.
func RawTracepointOpen(attr *BPFAttrRawTracepointOpen) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_RAW_TRACEPOINT_OPEN, attr, int(attr.Size()))
}

// BTFLoad verifies and loads BPF Type Format (BTF) metadata into the kernel,
// returning a new file descriptor associated with the metadata.
// BTF is described in more detail at https://www.kernel.org/doc/html/latest/bpf/btf.html.
//
// The attr.BTF parameter must point to valid memory providing
// attr.BTFSize bytes of BTF binary metadata.
//
// The returned file descriptor can be passed to other
// functions such as ProgramLoad or MapCreate to
// associate the BTF with those objects.
//
// Similar toProgramLoad, BTFLoad has optional
// parameters to specify a attr.BTFLog, attr.BTFLogSize and
// attr.BTFLogLevel which allow the kernel to return freeform log
// output regarding the BTF verification process.
func BTFLoad(attr *BPFAttrBTFLoad) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_BTF_LOAD, attr, int(attr.Size()))
}

// BTFGetFDByID opens a file descriptor for the BPF Type Format (BTF) corresponding to attr.ID.
func BTFGetFDByID(attr *BPFAttrGetID) error {
	return bpfNoReturn(bpftypes.BPF_BTF_GET_FD_BY_ID, attr, int(attr.Size()))
}

// TaskFDQuery obtains information about eBPF programs associated with the
//	target process identified by attr.PID and attr.FD.
//
//	If the attr.PID and attr.fd are associated with a tracepoint, kprobe
//	or uprobe perf event, then the attr.ProgID and attr.FDType will
//	be populated with the eBPF program id and file descriptor type
//	of type bpftypes.BPFTaskFDType. If associated with a kprobe or
//	uprobe, the  attr.ProbeOffset and attr.ProbeAddr will also be
//	populated. Optionally, if attr.Buf is provided, then up to
//	attr.BufLen bytes of attr.Buf will be populated with the name of
//	the tracepoint, kprobe or uprobe.
//
//	The resulting attr.ProgID may be introspected in deeper detail
//	using ProgramGetFDByID and ObjectGetInfoByFD.
func TaskFDQuery(attr *BPFAttrTaskFDQuery) error {
	return bpfNoReturn(bpftypes.BPF_TASK_FD_QUERY, attr, int(attr.Size()))
}

// MapLookupAndDeleteElement looks up an element with the given attr.Key in the map referred to
//	by the file descriptor attr.MapFD, and if found, delete the element.
//
//	The bpftypes.BPF_MAP_TYPE_QUEUE and bpftypes.BPF_MAP_TYPE_STACK map types
//	implement this command as a "pop" operation, deleting the top
//	element rather than one corresponding to attr.Key.
//	The attr.Key parameter should be zeroed when issuing this operation for these map types.
//
//	This command is only valid for the following map types:
//	* bpftypes.BPF_MAP_TYPE_QUEUE
//	* bpftypes.BPF_MAP_TYPE_STACK
func MapLookupAndDeleteElement(attr *BPFAttrMapElem) error {
	return bpfNoReturn(bpftypes.BPF_MAP_LOOKUP_AND_DELETE_ELEM, attr, int(attr.Size()))
}

// MapFreeze freezes the permissions of the specified map.
//
// Write permissions may be frozen by passing zero attr.Flags.
// Upon success, no future syscall invocations may alter the
// map state of attr.MapFD. Write operations from eBPF programs
// are still possible for a frozen map.
//
// Not supported for maps of type bpftypes.BPF_MAP_TYPE_STRUCT_OPS.
func MapFreeze(attr *BPFAttrMapElem) error {
	return bpfNoReturn(bpftypes.BPF_MAP_FREEZE, attr, int(attr.Size()))
}

// BTFGetNextID fetches the next BPF Type Format (BTF) object currently loaded into the kernel.
//
// Looks for the BTF object with an id greater than attr.ID and updates attr.NextID on success.
// If no other BTF objects remain with ids higher than attr.ID, an error with errno ENOENT(2) is returned.
func BTFGetNextID(attr *BPFAttrGetID) error {
	return bpfNoReturn(bpftypes.BPF_BTF_GET_NEXT_ID, attr, int(attr.Size()))
}

// MapLookupBatch iterates and fetches multiple elements in a map.
//
// Two opaque values are used to manage batch operations,
// attr.InBatch and attr.OutBatch. Initially, attr.InBatch must be set
// to NULL to begin the batched operation. After each subsequent
// MapLookupBatch, the caller should pass the resultant
// attr.OutBatch as the attr.InBatch for the next operation to
// continue iteration from the current point.
//
// The attr.Keys and attr.Values are output parameters which must point
// to memory large enough to hold attr.Count items based on the key
// and value size of the map attr.MapFD. The attr.Keys buffer must be
// of sizeof(key_type) * attr.Count. The attr.Values buffer must be of
// sizeof(value_type) * attr.Count.
//
// The attr.ElemFlags argument may be specified as one of the
// following:
//
// BPFMapElemLock
//   Look up the value of a spin-locked map without
// 	 returning the lock. This must be specified if the
// 	 elements contain a spinlock.
//
// On success, attr.Count elements from the map are copied into the
// user buffer, with the keys copied into attr.Keys and the values
// copied into the corresponding indices in attr.Values.
//
// If an error is returned and errno is not syscall.EFAULT, attr.Count
// is set to the number of successfully processed elements.
func MapLookupBatch(attr *BPFAttrMapBatch) error {
	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapLookupBatch) {
		return fmt.Errorf("batch lookup not supported: %w", ErrNotSupported)
	}

	return bpfNoReturn(bpftypes.BPF_MAP_LOOKUP_BATCH, attr, int(attr.Size()))
}

// MapLookupBatchAndDelete iterates and delete all elements in a map.
// This operation has the same behavior as
// MapLookupBatch with two exceptions:
//	* Every element that is successfully returned is also deleted
//	  from the map. This is at least attr.Count elements. Note that
//	  attr.Count is both an input and an output parameter.
//	* Upon returning with errno set to syscall.EFAULT, up to
//	  attr.Count elements may be deleted without returning the keys
//	  and values of the deleted elements.
func MapLookupBatchAndDelete(attr *BPFAttrMapBatch) error {
	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapLookupAndDeleteBatch) {
		return fmt.Errorf("batch lookup and delete not supported: %w", ErrNotSupported)
	}

	return bpfNoReturn(bpftypes.BPF_MAP_LOOKUP_AND_DELETE_BATCH, attr, int(attr.Size()))
}

// MapUpdateBatch updates multiple elements in a map by *key*.
//
// The attr.Keys and attr.Value are input parameters which must point
// to memory large enough to hold attr.Count items based on the key
// and value size of the map attr.MapFD. The attr.Keys buffer must be
// of sizeof(key_type) * attr.Count. The attr.Values buffer must be of
// sizeof(value_type) * attr.Count.
//
// Each element specified in attr.Keys is sequentially updated to the
// value in the corresponding index in attr.Values. The attr.InBatch
// and attr.OutBatch parameters are ignored and should be zeroed.
//
// The attr.ElemFlags argument should be specified as one of the
// following:
//
// BPFMapElemAny
//   Create new elements or update a existing elements.
// BPFMapElemNoExists
// 	 Create new elements only if they do not exist.
// BPFMapElemExists
// 	 Update existing elements.
// BPFMapElemLock
// 	 Update spin_lock-ed map elements. This must be
// 	 specified if the map value contains a spinlock.
//
// On success, attr.Count elements from the map are updated.
//
// If an error is returned and errno is not syscall.EFAULT, attr.Count
// is set to the number of successfully processed elements.
func MapUpdateBatch(attr *BPFAttrMapBatch) error {
	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapUpdateBatch) {
		return fmt.Errorf("batch update not supported: %w", ErrNotSupported)
	}

	err := bpfNoReturn(bpftypes.BPF_MAP_UPDATE_BATCH, attr, int(attr.Size()))
	if syserr, ok := err.(*BPFSyscallError); ok {
		syserr.Err = map[syscall.Errno]string{
			syscall.E2BIG:  "the number of elements in the map reached the *max_entries* limit specified at map creation time",
			syscall.EEXIST: "attr.Flags specifies BPFMapElemNoExists and the element with attr.Keys[*] already exists in the map",
			syscall.ENOENT: "attr.Flags specifies BPFMapElemExists and the element with attr.Keys[*] does not exist in the map",
		}[syserr.Errno]
		return syserr
	}

	return err
}

// MapDeleteBatch deletes multiple elements in a map.
//
// The attr.Keys parameter is an input parameter which must point
// to memory large enough to hold attr.Count items based on the key
// size of the map attr.MapFD, that is, sizeof(key_type) * attr.Count.
//
// Each element specified in attr.Keys is sequentially deleted. The
// attr.InBatch, attr.OutBatch, and attr.Values parameters are ignored
// and should be zeroed.
//
// The attr.ElemFlags argument may be specified as one of the
// following:
//
// BPFMapElemLock
// 	 Look up the value of a spin-locked map without
// 	 returning the lock. This must be specified if the
// 	 elements contain a spinlock.
//
// On success, attr.Count elements from the map are updated.
//
// If an error is returned and errno is not syscall.EFAULT, attr.Count
// is set to the number of successfully processed elements. If
// errno is syscall.EFAULT, up to attr.Count elements may be been
// deleted.
func MapDeleteBatch(attr *BPFAttrMapBatch) error {
	// If the user attempts to use a unsupported feature, tell them to avoid unexpected behavior
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapDeleteBatch) {
		return fmt.Errorf("batch lookup and delete not supported: %w", ErrNotSupported)
	}

	return bpfNoReturn(bpftypes.BPF_MAP_DELETE_BATCH, attr, int(attr.Size()))
}

// LinkCreate attaches an eBPF program to a attr.TargetFD at the specified
// attr.AttachType hook and return a file descriptor handle for
// managing the link.
func LinkCreate(attr *BPFAttrLinkCreate) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_LINK_CREATE, attr, int(attr.Size()))
}

// LinkUpdate updates the eBPF program in the specified attr.LinkFD to attr.NewProgFD.
func LinkUpdate(attr *BPFAttrLinkUpdate) error {
	return bpfNoReturn(bpftypes.BPF_LINK_UPDATE, attr, int(attr.Size()))
}

// LinkGetFDByID opens a file descriptor for the eBPF Link corresponding to attr.LinkID
func LinkGetFDByID(attr *BPFAttrGetID) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_LINK_GET_FD_BY_ID, attr, int(attr.Size()))
}

// LinkGetNextID fetches the next eBPF program currently loaded into the kernel.
// Looks for the eBPF link with an id greater than attr.ID and updates attr.NextID on success.
// If no other eBPF links remain with ids higher than attr.ID, an error with errno ENOENT(2) is returned.
func LinkGetNextID(attr *BPFAttrGetID) error {
	return bpfNoReturn(bpftypes.BPF_LINK_GET_NEXT_ID, attr, int(attr.Size()))
}

// EnableStats enables eBPF runtime statistics gathering.
// Runtime statistics gathering for the eBPF runtime is disabled
// by default to minimize the corresponding performance overhead.
// This command enables statistics globally.
//
// Multiple programs may independently enable statistics.
// After gathering the desired statistics, eBPF runtime statistics
// may be disabled again by calling Close() for the file
// descriptor returned by this function. Statistics will only be
// disabled system-wide when all outstanding file descriptors
// returned by prior calls for this subcommand are closed.
func EnableStats(attr *BPFAttrEnableStats) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_ENABLE_STATS, attr, int(attr.Size()))
}

// IterCreate creates an iterator on top of the specified attr.LinkFD (as
// previously created using LinkUpdate) and return a
// file descriptor that can be used to trigger the iteration.
//
// If the resulting file descriptor is pinned to the filesystem
// using ObjectPin, then subsequent syscall.Read syscalls
// for that path will trigger the iterator to read kernel state
// using the eBPF program attached to attr.LinkFD.
func IterCreate(attr *BPFAttrIterCreate) (fd BPFfd, err error) {
	return Bpf(bpftypes.BPF_ITER_CREATE, attr, int(attr.Size()))
}

// LinkDetach forcefully detaches the specified attr.LinkFD from its
// corresponding attachment point.
func LinkDetach(attr *BPFAttrLinkDetach) error {
	return bpfNoReturn(bpftypes.BPF_LINK_DETACH, attr, int(attr.Size()))
}

// ProgBindMap Bind a map to the lifetime of an eBPF program.
//
// The map identified by attr.MapFD is bound to the program
// identified by attr.ProgFD and only released when attr.ProgFD is
// released. This may be used in cases where metadata should be
// associated with a program which otherwise does not contain any
// references to the map (for example, embedded in the eBPF
// program instructions).
func ProgBindMap(attr *BPFAttrProgBindMap) error {
	return bpfNoReturn(bpftypes.BPF_PROG_BIND_MAP, attr, int(attr.Size()))
}
