package perf

import (
	"fmt"
	"syscall"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	bpfSyscall "github.com/dylandreimerink/gobpfld/internal/syscall"
	"golang.org/x/sys/unix"
)

// Event represents an linux perf event in userspace.
type Event struct {
	Type bpfSyscall.PerfType

	fd              FD
	attachedProgram bpfsys.BPFfd
	kprobe          *KProbe
	uprobe          *UProbe
}

// AttachBPFProgram attach a loaded BPF program to the perf event.
func (e *Event) AttachBPFProgram(programFD bpfsys.BPFfd) error {
	// TODO check that fd is set

	// Attach BPF program
	err := bpfSyscall.IOCtl(int(e.fd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(programFD))
	if err != nil {
		return err
	}

	// Enable the perf event
	err = bpfSyscall.IOCtl(int(e.fd), unix.PERF_EVENT_IOC_ENABLE, 0)
	if err != nil {
		return err
	}

	e.attachedProgram = programFD

	return nil
}

func (e *Event) DetachBPFProgram() error {
	// disable the perf event
	err := bpfSyscall.IOCtl(int(e.fd), unix.PERF_EVENT_IOC_DISABLE, 0)
	if err != nil {
		return fmt.Errorf("ioctl disable perf event: %w", err)
	}

	// close the fd of the perf event
	err = syscall.Close(int(e.fd))
	if err != nil {
		return fmt.Errorf("close perf event: %w", err)
	}

	if e.kprobe != nil {
		// ignore error
		err = e.kprobe.Clear()
		if err != nil {
			return fmt.Errorf("clear kprobe: %w", err)
		}
	}
	if e.uprobe != nil {
		// ignore error
		err = e.uprobe.Clear()
		if err != nil {
			return fmt.Errorf("clear uprobe: %w", err)
		}
	}

	return nil
}

type FD uint32

// Close closes a file descriptor
func (fd FD) Close() error {
	err := unix.Close(int(fd))
	if err != nil {
		return err
	}

	return nil
}

// OpenTracepointEvent opens a perf event for an existing tracepoint. Tracepoint perf events can be used to to attach
// BPF_PROG_TYPE_TRACEPOINT applications to.
func OpenTracepointEvent(category, name string) (*Event, error) {
	id, err := getTracepointID(category, name)
	if err != nil {
		return nil, fmt.Errorf("getTracepointID: %w", err)
	}

	return perfEventOpen(bpfSyscall.PerfEventAttr{
		Type:   bpfSyscall.PERF_TYPE_TRACEPOINT,
		Size:   bpfSyscall.AttrSize,
		Config: uint64(id),
	}, -1, 0, -1, bpfSyscall.PerfEventOpenFDCloseOnExit)
}

// TODO add open event buffer function

func OpenKProbeEvent(kprobeOpts KProbeOpts) (*Event, error) {
	kprobe, err := newKProbe(kprobeOpts)
	if err != nil {
		return nil, fmt.Errorf("kprobe: %w", err)
	}

	// TODO using the debugfs and tracepoint type is apparently legacy, the new way to do it is using
	//   dynamic PMU's. Couldn't get this to work, so in future figure it out and add as preferred method
	//   and keep this one as fallback for older kernels

	event, err := perfEventOpen(bpfSyscall.PerfEventAttr{
		Type:   bpfSyscall.PERF_TYPE_TRACEPOINT,
		Size:   bpfSyscall.AttrSize,
		Config: uint64(kprobe.ID),
	}, -1, 0, -1, bpfSyscall.PerfEventOpenFDCloseOnExit)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %w", err)
	}

	event.kprobe = kprobe

	return event, nil
}

func OpenUProbeEvent(uprobeOpts UProbeOpts) (*Event, error) {
	uprobe, err := newUProbe(uprobeOpts)
	if err != nil {
		return nil, fmt.Errorf("uprobe: %w", err)
	}

	// TODO add CPU and PID options since they are allowed for uprobes to trace specific programs

	// TODO using the debugfs and tracepoint type is apparently legacy, the new way to do it is using
	//   dynamic PMU's. Couldn't get this to work, so in future figure it out and add as preferred method
	//   and keep this one as fallback for older kernels

	event, err := perfEventOpen(bpfSyscall.PerfEventAttr{
		Type:   bpfSyscall.PERF_TYPE_TRACEPOINT,
		Size:   bpfSyscall.AttrSize,
		Config: uint64(uprobe.ID),
	}, -1, 0, -1, bpfSyscall.PerfEventOpenFDCloseOnExit)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %w", err)
	}

	event.uprobe = uprobe

	return event, nil
}

// perfEventOpen is a wrapper around the perf_event_open syscall.
func perfEventOpen(
	attr bpfSyscall.PerfEventAttr,
	pid,
	cpu,
	groupFD int,
	flags bpfSyscall.PerfEventOpenFlags,
) (*Event, error) {
	fd, err := bpfSyscall.PerfEventOpen(attr, pid, cpu, groupFD, flags)
	if err != nil {
		return nil, err
	}

	return &Event{
		Type: attr.Type,
		fd:   FD(fd),
	}, nil
}
