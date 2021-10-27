package perf

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"golang.org/x/sys/unix"
)

// Event represents an linux perf event in userspace.
type Event struct {
	Type Type

	fd              FD
	attachedProgram bpfsys.BPFfd
	kProbe          *KProbe
}

// AttachBPFProgram attach a loaded BPF program to the perf event.
func (e *Event) AttachBPFProgram(programFD bpfsys.BPFfd) error {
	// TODO check that fd is set

	// Attach BPF program
	err := ioctl(int(e.fd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(programFD))
	if err != nil {
		return err
	}

	// Enable the perf event
	err = ioctl(int(e.fd), unix.PERF_EVENT_IOC_ENABLE, 0)
	if err != nil {
		return err
	}

	if e.kProbe != nil {
		err := e.kProbe.Enable()
		if err != nil {
			return fmt.Errorf("kprobe enable: %w", err)
		}
	}

	e.attachedProgram = programFD

	return nil
}

func (e *Event) DetachBPFProgram() error {
	if e.kProbe != nil {
		err := e.kProbe.Disable()
		if err != nil {
			return fmt.Errorf("kprobe disable: %w", err)
		}
	}

	// disable the perf event
	err := ioctl(int(e.fd), unix.PERF_EVENT_IOC_DISABLE, 0)
	if err != nil {
		return fmt.Errorf("ioctl disable perf event: %w", err)
	}

	// close the fd of the perf event
	err = syscall.Close(int(e.fd))
	if err != nil {
		return fmt.Errorf("close perf event: %w", err)
	}

	if e.kProbe != nil {
		// ignore error
		err = e.kProbe.Clear()
		if err != nil {
			return fmt.Errorf("clear kprobe: %w", err)
		}
	}

	return nil
}

type SyscallError struct {
	// Context specific error information since the same code can have different
	// meaning depending on context
	Err string
	// The underlaying syscall error number
	Errno unix.Errno
}

func (e *SyscallError) Error() string {
	if e.Err == "" {
		return fmt.Sprintf("%s (%d)", e.Errno.Error(), e.Errno)
	}

	return fmt.Sprintf("%s (%s)(%d)", e.Err, e.Errno.Error(), e.Errno)
}

type FD uint32

// Close closes a file descriptor
func (fd FD) Close() error {
	_, _, errno := unix.Syscall(unix.SYS_CLOSE, uintptr(fd), 0, 0)
	if errno != 0 {
		return &SyscallError{
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

// Type https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/perf_event.h#L32
type Type uint32

const (
	// TYPE_HARDWARE This indicates one of the "generalized"  hardware  events
	// provided  by the kernel.  See the config field definition
	// for more details.
	TYPE_HARDWARE Type = iota

	// TYPE_SOFTWARE This indicates one of the  software-defined  events  provided
	// by  the  kernel  (even  if  no hardware support is
	// available).
	TYPE_SOFTWARE

	// TYPE_TRACEPOINT This indicates a tracepoint provided by the kernel tracepoint infrastructure.
	TYPE_TRACEPOINT

	// TYPE_HW_CACHE  This  indicates  a hardware cache event. This has a special encoding,
	// described in the config field definition.
	TYPE_HW_CACHE

	// TYPE_RAW This indicates a "raw" implementation-specific  event  in
	// the config field.
	TYPE_RAW

	// TYPE_BREAKPOINT This  indicates  a hardware breakpoint as provided by the CPU.
	// Breakpoints can be read/write accesses  to  an  address as well as execution of an instruction address.
	TYPE_BREAKPOINT
)

// AttrFlags are used to pass a lot of boolean flags efficiently to the kerenl
type AttrFlags uint64

const (
	// AttrFlagsDisabled off by default
	AttrFlagsDisabled AttrFlags = 1 << iota
	// AttrFlagsInherit children inherit it
	AttrFlagsInherit
	// AttrFlagsPinned must always be on PMU
	AttrFlagsPinned
	// AttrFlagsExclusive only group on PMU
	AttrFlagsExclusive
	// AttrFlagsExcludeUser don't count user
	AttrFlagsExcludeUser
	// AttrFlagsExcludeKernel ditto kernel
	AttrFlagsExcludeKernel
	// AttrFlagsExcludeHV ditto hypervisor
	AttrFlagsExcludeHV
	// AttrFlagsExcludeIdle don't count when idle
	AttrFlagsExcludeIdle
	// AttrFlagsMmap include mmap data
	AttrFlagsMmap
	// AttrFlagsComm include comm data
	AttrFlagsComm
	// AttrFlagsFreq use freq, not period
	AttrFlagsFreq
	// AttrFlagsInheritStat per task counts
	AttrFlagsInheritStat
	// AttrFlagsEnableOnExec next exec enables
	AttrFlagsEnableOnExec
	// AttrFlagsTask trace fork/exit
	AttrFlagsTask
	// AttrFlagsWatermark wakeup_watermark
	AttrFlagsWatermark
	// AttrFlagsPreciseIPConstantSkid SAMPLE_IP must have constant skid, See also PERF_RECORD_MISC_EXACT_IP
	AttrFlagsPreciseIPConstantSkid AttrFlags = 1 << 15
	// AttrFlagsPreciseIPRequestZeroSkid SAMPLE_IP requested to have 0 skid, See also PERF_RECORD_MISC_EXACT_IP
	AttrFlagsPreciseIPRequestZeroSkid AttrFlags = 1 << 16
	// AttrFlagsPreciseIPRequireZeroSkid SAMPLE_IP must have 0 skid, See also PERF_RECORD_MISC_EXACT_IP
	AttrFlagsPreciseIPRequireZeroSkid AttrFlags = 1<<16 + 1<<15
)

const (
	// AttrFlagsMmapData non-exec mmap data
	AttrFlagsMmapData = 1 << (17 + iota)
	// AttrFlagsSampleIDAll sample_type all events
	AttrFlagsSampleIDAll
	// AttrFlagsExcludeHost don't count in host
	AttrFlagsExcludeHost
	// AttrFlagsExcludeGuest don't count in guest
	AttrFlagsExcludeGuest
	// AttrFlagsExcludeCallchainKernel exclude kernel callchains
	AttrFlagsExcludeCallchainKernel
	// AttrFlagsExcludeCallchainUser exclude user callchains
	AttrFlagsExcludeCallchainUser
	// AttrFlagsMmap2 include mmap with inode data
	AttrFlagsMmap2
	// AttrFlagsCommExec flag comm events that are due to an exec
	AttrFlagsCommExec
	// AttrFlagsUseClockid use @clockid for time fields
	AttrFlagsUseClockid
	// AttrFlagsContextSwitch context switch data
	AttrFlagsContextSwitch
	// AttrFlagsWriteBackward Write ring buffer from end to beginning
	AttrFlagsWriteBackward
	// AttrFlagsNamespaces include namespaces data
	AttrFlagsNamespaces
	// AttrFlagsKsymbol include ksymbol events
	AttrFlagsKsymbol
	// AttrFlagsBpfEvent include bpf events
	AttrFlagsBpfEvent
	// AttrFlagsAuxOutput generate AUX records instead of events
	AttrFlagsAuxOutput
	// AttrFlagsCgroup include cgroup events
	AttrFlagsCgroup
	// AttrFlagsTextPoke include text poke events
	AttrFlagsTextPoke
	// AttrFlagsBuildID use build id in mmap2 events
	AttrFlagsBuildID
	// AttrFlagsInheritThread children only inherit if cloned with CLONE_THREAD
	AttrFlagsInheritThread
	// AttrFlagsRemoveOnExec event is removed from task on exec
	AttrFlagsRemoveOnExec
	// AttrFlagsSigtrap send synchronous SIGTRAP on event
	AttrFlagsSigtrap
)

// perfEventAttr is the go version of the perf_event_attr struct as defined by the kernel.
// https://elixir.bootlin.com/linux/v5.14.14/source/include/uapi/linux/perf_event.h#L338
type perfEventAttr struct {
	Type   Type
	Size   uint32
	Config uint64
	// union of sample_period and sample_frequency
	SamplePeriodFreq uint64
	SampleType       uint64
	AttrFlags        AttrFlags
	// union of wakeup_events and wakeup_watermark
	WakeupEventsWatermark uint32
	BPType                uint32
	// union of bp_addr, kprobe_func, uprobe_path, and config1
	BPAddr uint64
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
	AUXWatermark uint32
	// __reserved_2
	_             uint16
	AUXSampleSize uint32
	// __reserved_3
	_       uint32
	SigData uint64
}

const attrSize = uint32(unsafe.Sizeof(perfEventAttr{}))

// OpenTracepointEvent opens a perf event for an existing tracepoint. Tracepoint perf events can be used to to attach
// BPF_PROG_TYPE_TRACEPOINT applications to.
func OpenTracepointEvent(category, name string) (*Event, error) {
	id, err := getTracepointID(category, name)
	if err != nil {
		return nil, fmt.Errorf("getTracepointID: %w", err)
	}

	return perfEventOpen(perfEventAttr{
		Type:   TYPE_TRACEPOINT,
		Size:   attrSize,
		Config: uint64(id),
	}, -1, 0, -1, EventOpenFDCloseOnExit)
}

// TODO add open event buffer function

func OpenKProbeEvent(kprobeOpts KprobeOpts) (*Event, error) {
	kprobe, err := newKProbe(kprobeOpts)
	if err != nil {
		return nil, fmt.Errorf("kprobe: %w", err)
	}

	event, err := perfEventOpen(perfEventAttr{
		Type:   TYPE_TRACEPOINT,
		Size:   attrSize,
		Config: uint64(kprobe.ID),
	}, -1, 0, -1, EventOpenFDCloseOnExit)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %w", err)
	}

	event.kProbe = kprobe

	return event, nil
}

// TODO add open uprobe event

type EventOpenFlags uintptr

const (
	// EventOpenFDNoGroup This  flag  tells the event to ignore the group_fd parameter ex‐
	// cept for the purpose of setting up output redirection using  the
	// PERF_FLAG_FD_OUTPUT flag.
	EventOpenFDNoGroup EventOpenFlags = 1 << iota

	// EventOpenFDOutput This flag re-routes the event's sampled output to instead be in‐
	// cluded in the mmap buffer of the event specified by group_fd.
	EventOpenFDOutput

	// EventOpenPIDCgroup This  flag  tells the event to ignore the group_fd parameter ex‐
	// cept for the purpose of setting up output redirection using  the
	// PERF_FLAG_FD_OUTPUT flag.
	EventOpenPIDCgroup

	// EventOpenFDCloseOnExit This  flag  enables the close-on-exec flag for the created event
	// file descriptor, so that the file  descriptor  is  automatically
	// closed  on  execve(2).   Setting the close-on-exec flags at cre‐
	// ation time, rather than later with  fcntl(2),  avoids  potential
	// race    conditions    where    the    calling   thread   invokes
	// perf_event_open() and fcntl(2)  at  the  same  time  as  another
	// thread calls fork(2) then execve(2).
	EventOpenFDCloseOnExit
)

// perfEventOpen is a wrapper around the perf_event_open syscall.
func perfEventOpen(attr perfEventAttr, pid, cpu, groupFD int, flags EventOpenFlags) (*Event, error) {
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
		return nil, &SyscallError{
			Errno: errno,
			Err:   perfEventOpenErrors[errno],
		}
	}

	return &Event{
		Type: attr.Type,
		fd:   FD(fd),
	}, nil
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
