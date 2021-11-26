package syscall

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PerfEventAttr is the go version of the perf_event_attr struct as defined by the kernel.
// https://elixir.bootlin.com/linux/v5.14.14/source/include/uapi/linux/perf_event.h#L338
type PerfEventAttr struct {
	Type   PerfType
	Size   uint32
	Config uint64
	// union of sample_period and sample_frequency
	SamplePeriodFreq uint64
	SampleType       uint64
	AttrFlags        PerfAttrFlags
	// union of wakeup_events and wakeup_watermark
	WakeupEventsWatermark uint32
	BPType                uint32
	// union of bp_addr, kprobe_func, uprobe_path, and config1
	BPAddr uintptr
	// union of bp_len, kprobe_addr, probe_offset, and config2
	BPLen uint64
	// Unum of perf_branch_sample_type
	BranchSampleType uint64
	// Defines set of user regs to dump on samples.
	// See asm/perf_regs.h for details.
	SampleRegsUser uint64
	// Defines size of the user stack to dump on samples.
	SampleStackUser uint32
	ClockID         int32
	// Defines set of regs to dump for each sample
	// state captured on:
	//  - precise = 0: PMU interrupt
	//  - precise > 0: sampled instruction
	//
	// See asm/perf_regs.h for details.
	SampleRegsIntr uint64
	// Wakeup watermark for AUX area
	AUXWatermark   uint32
	SampleMaxStack uint16
	// __reserved_2
	_             uint16
	AUXSampleSize uint32
	// __reserved_3
	_       uint32
	SigData uint64
}

const AttrSize = uint32(unsafe.Sizeof(PerfEventAttr{}))

// PerfType https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/perf_event.h#L32
type PerfType uint32

const (
	// PERF_TYPE_HARDWARE This indicates one of the "generalized"  hardware  events
	// provided  by the kernel.  See the config field definition
	// for more details.
	PERF_TYPE_HARDWARE PerfType = iota

	// PERF_TYPE_SOFTWARE This indicates one of the  software-defined  events  provided
	// by  the  kernel  (even  if  no hardware support is
	// available).
	PERF_TYPE_SOFTWARE

	// PERF_TYPE_TRACEPOINT This indicates a tracepoint provided by the kernel tracepoint infrastructure.
	PERF_TYPE_TRACEPOINT

	// PERF_TYPE_HW_CACHE  This  indicates  a hardware cache event. This has a special encoding,
	// described in the config field definition.
	PERF_TYPE_HW_CACHE

	// PERF_TYPE_RAW This indicates a "raw" implementation-specific  event  in
	// the config field.
	PERF_TYPE_RAW

	// PERF_TYPE_BREAKPOINT This  indicates  a hardware breakpoint as provided by the CPU.
	// Breakpoints can be read/write accesses  to  an  address as well as execution of an instruction address.
	PERF_TYPE_BREAKPOINT
)

// PerfAttrFlags are used to pass a lot of boolean flags efficiently to the kerenl
type PerfAttrFlags uint64

const (
	// PerfAttrFlagsDisabled off by default
	PerfAttrFlagsDisabled PerfAttrFlags = 1 << iota
	// PerfAttrFlagsInherit children inherit it
	PerfAttrFlagsInherit
	// PerfAttrFlagsPinned must always be on PMU
	PerfAttrFlagsPinned
	// PerfAttrFlagsExclusive only group on PMU
	PerfAttrFlagsExclusive
	// PerfAttrFlagsExcludeUser don't count user
	PerfAttrFlagsExcludeUser
	// PerfAttrFlagsExcludeKernel ditto kernel
	PerfAttrFlagsExcludeKernel
	// PerfAttrFlagsExcludeHV ditto hypervisor
	PerfAttrFlagsExcludeHV
	// PerfAttrFlagsExcludeIdle don't count when idle
	PerfAttrFlagsExcludeIdle
	// PerfAttrFlagsMmap include mmap data
	PerfAttrFlagsMmap
	// PerfAttrFlagsComm include comm data
	PerfAttrFlagsComm
	// PerfAttrFlagsFreq use freq, not period
	PerfAttrFlagsFreq
	// PerfAttrFlagsInheritStat per task counts
	PerfAttrFlagsInheritStat
	// PerfAttrFlagsEnableOnExec next exec enables
	PerfAttrFlagsEnableOnExec
	// PerfAttrFlagsTask trace fork/exit
	PerfAttrFlagsTask
	// PerfAttrFlagsWatermark wakeup_watermark
	PerfAttrFlagsWatermark
	// PerfAttrFlagsPreciseIPConstantSkid SAMPLE_IP must have constant skid, See also PERF_RECORD_MISC_EXACT_IP
	PerfAttrFlagsPreciseIPConstantSkid PerfAttrFlags = 1 << 15
	// PerfAttrFlagsPreciseIPRequestZeroSkid SAMPLE_IP requested to have 0 skid, See also PERF_RECORD_MISC_EXACT_IP
	PerfAttrFlagsPreciseIPRequestZeroSkid PerfAttrFlags = 1 << 16
	// PerfAttrFlagsPreciseIPRequireZeroSkid SAMPLE_IP must have 0 skid, See also PERF_RECORD_MISC_EXACT_IP
	PerfAttrFlagsPreciseIPRequireZeroSkid PerfAttrFlags = 1<<16 + 1<<15
)

type PerfEventOpenFlags uintptr

const (
	// PerfEventOpenFDNoGroup This  flag  tells the event to ignore the group_fd parameter ex‐
	// cept for the purpose of setting up output redirection using  the
	// PERF_FLAG_FD_OUTPUT flag.
	PerfEventOpenFDNoGroup PerfEventOpenFlags = 1 << iota

	// PerfEventOpenFDOutput This flag re-routes the event's sampled output to instead be in‐
	// cluded in the mmap buffer of the event specified by group_fd.
	PerfEventOpenFDOutput

	// PerfEventOpenPIDCgroup This  flag  tells the event to ignore the group_fd parameter ex‐
	// cept for the purpose of setting up output redirection using  the
	// PERF_FLAG_FD_OUTPUT flag.
	PerfEventOpenPIDCgroup

	// PerfEventOpenFDCloseOnExit This  flag  enables the close-on-exec flag for the created event
	// file descriptor, so that the file  descriptor  is  automatically
	// closed  on  execve(2).   Setting the close-on-exec flags at cre‐
	// ation time, rather than later with  fcntl(2),  avoids  potential
	// race    conditions    where    the    calling   thread   invokes
	// perf_event_open() and fcntl(2)  at  the  same  time  as  another
	// thread calls fork(2) then execve(2).
	PerfEventOpenFDCloseOnExit
)

// PerfEventOpen is a wrapper around the perf_event_open syscall.
func PerfEventOpen(attr PerfEventAttr, pid, cpu, groupFD int, flags PerfEventOpenFlags) (uintptr, error) {
	fd, _, errno := unix.Syscall6(
		unix.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr)),
		uintptr(pid),
		uintptr(cpu),
		uintptr(groupFD),
		uintptr(flags),
		0,
	)
	if errno != 0 {
		return 0, &Error{
			Errno: errno,
			Err:   perfEventOpenErrors[errno],
		}
	}

	return fd, nil
}

var perfEventOpenErrors = map[syscall.Errno]string{
	unix.E2BIG: "The perf_event_attr size value is too small (smaller " +
		"than PERF_ATTR_SIZE_VER0), too big (larger than the page  size), " +
		"or  larger  than the kernel supports and the extra bytes are not " +
		"zero.  When E2BIG is returned, the perf_event_attr size field is " +
		"overwritten by the kernel to be the size of the structure it was " +
		"expecting.",

	unix.EACCES: "The requested event  requires  CAP_PERFMON  (since " +
		"Linux  5.8)  or  CAP_SYS_ADMIN permissions (or a more permissive " +
		"perf_event paranoid setting).  Some common cases  where  an  un‐ " +
		"privileged  process  may  encounter  this  error: attaching to a " +
		"process owned by a different user; monitoring all processes on a " +
		"given  CPU  (i.e.,  specifying  the pid argument as -1); and not " +
		"setting exclude_kernel when the paranoid setting requires it.",

	unix.EBADF: "The group_fd file descriptor is not  valid,  or,  if " +
		"PERF_FLAG_PID_CGROUP  is  set, the cgroup file descriptor in pid " +
		"is not valid.",

	unix.EBUSY: "Another event already has exclusive  access  to  the PMU.",

	unix.EFAULT: "The  attr  pointer points at an invalid memory address.",

	unix.EINVAL: "The specified event is invalid.  There are many pos‐ " +
		"sible  reasons  for this.  A not-exhaustive list: sample_freq is " +
		"higher than the maximum setting; the cpu to monitor does not ex‐ " +
		"ist;  read_format  is out of range; sample_type is out of range; " +
		"the flags value is out of range; exclusive or pinned set and the " +
		"event  is not a group leader; the event config values are out of " +
		"range or set reserved bits; the generic event  selected  is  not " +
		"supported;  or  there  is  not  enough  room to add the selected " +
		"event.",

	unix.EINTR: "Returned when trying to mix perf and ftrace handling for  a  uprobe.",

	unix.EMFILE: "Each  opened  event uses one file descriptor.  If a large number " +
		"of events are opened, the per-process limit  on  the  number  of " +
		"open file descriptors will be reached, and no more events can be " +
		"created.",

	unix.ENODEV: "Returned when the event involves a feature not supported by the current CPU.",

	unix.ENOENT: "Returned  if  the type setting is not valid. " +
		"This error is also returned for some unsupported generic events.",

	unix.ENOSPC: "Prior to Linux 3.3, if there was not enough room for the  event, " +
		"ENOSPC  was returned.  In Linux 3.3, this was changed to EINVAL. " +
		"ENOSPC is still returned if  you  try  to  add  more  breakpoint " +
		"events than supported by the hardware.",

	unix.ENOSYS: "Returned  if PERF_SAMPLE_STACK_USER is set in sample_type and it " +
		"is not supported by hardware.",

	unix.EOPNOTSUPP: "Returned if an event requiring a specific  hardware  feature  is " +
		"requested  but  there is no hardware support.  This includes re‐ " +
		"questing low-skid events if not supported, branch tracing if  it " +
		"is not available, sampling if no PMU interrupt is available, and " +
		"branch stacks for software events.",

	unix.EOVERFLOW: "(since Linux 4.8) " +
		"Returned  if  PERF_SAMPLE_CALLCHAIN  is   requested   and   sam‐ " +
		"ple_max_stack   is   larger   than   the  maximum  specified  in " +
		"/proc/sys/kernel/perf_event_max_stack.",

	unix.EPERM: "Returned on many (but not all) architectures when an unsupported " +
		"exclude_hv,  exclude_idle,  exclude_user, or exclude_kernel set‐ " +
		"ting is specified. \n" +
		"It can also happen, as with EACCES, when the requested event re‐ " +
		"quires  CAP_PERFMON  (since  Linux 5.8) or CAP_SYS_ADMIN permis‐ " +
		"sions (or a more permissive perf_event paranoid setting).   This " +
		"includes  setting  a  breakpoint on a kernel address, and (since " +
		"Linux 3.13) setting a kernel function-trace tracepoint.",

	unix.ESRCH: "Returned if attempting to attach to a process that does not exist.",
}
