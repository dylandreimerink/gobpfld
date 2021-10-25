package gobpfld

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"golang.org/x/sys/unix"
)

var _ BPFProgram = (*ProgramSocketFilter)(nil)

type ProgramSocketFilter struct {
	AbstractBPFProgram

	AttachedSocketFDs []int
}

type ProgSKFilterLoadOpts struct {
	VerifierLogLevel bpftypes.BPFLogLevel
	VerifierLogSize  int
}

func (p *ProgramSocketFilter) Load(opts ProgSKFilterLoadOpts) (log string, err error) {
	return p.load(bpfsys.BPFAttrProgramLoad{
		LogLevel: opts.VerifierLogLevel,
		LogSize:  uint32(opts.VerifierLogSize),
	})
}

// ErrProgramNotSocketFilterType is returned when attempting to attach a non-socket filter program to a socket.
var ErrProgramNotSocketFilterType = errors.New("the program is not loaded as an socket filter program and " +
	"thus can't be attached as such")

// SocketAttachControlFunc attaches a "socket filter" program to a network socket. This function is meant to be used
// as function pointer in net.Dialer.Control or net.ListenConfig.Control.
func (p *ProgramSocketFilter) SocketAttachControlFunc(network, address string, c syscall.RawConn) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		err = p.Attach(fd)
	})
	if err != nil {
		return fmt.Errorf("socket attach: %w", err)
	}
	if cerr != nil {
		return fmt.Errorf("socket attach: %w", cerr)
	}

	return nil
}

// Attach attempts to attach a filter program to the network socket indicated by the given file descriptor.
// This function can be used if network file descriptors are managed outside of the net package or when using
// the net.TCPListener.File function to get a duplicate file descriptor.
func (p *ProgramSocketFilter) Attach(fd uintptr) error {
	if !p.loaded {
		return ErrProgramNotLoaded
	}

	if p.ProgramType != bpftypes.BPF_PROG_TYPE_SOCKET_FILTER {
		return ErrProgramNotSocketFilterType
	}

	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, int(p.fd))
	if err != nil {
		return fmt.Errorf("syscall setsockopt: %w", err)
	}

	p.AttachedSocketFDs = append(p.AttachedSocketFDs, int(fd))

	return nil
}

type ProgSKFilterDetachOpts struct {
	// the file descriptor of the network socket from which the program should be detached
	Fd int
	// If true, the program will be detached from all network interfaces
	All bool
}

// Detach detaches the program from one or all sockets.
func (p *ProgramSocketFilter) Detach(settings ProgSKFilterDetachOpts) error {
	if settings.All {
		for _, fd := range p.AttachedSocketFDs {
			err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, int(p.fd))
			if err != nil {
				return fmt.Errorf("syscall setsockopt: %w", err)
			}
		}

		// Clear attached socket fd's slice
		p.AttachedSocketFDs = nil
		return nil
	}

	err := syscall.SetsockoptInt(settings.Fd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, int(p.fd))
	if err != nil {
		return fmt.Errorf("syscall setsockopt: %w", err)
	}

	// Delete the FD from the list of attached socket fd's
	for i, fd := range p.AttachedSocketFDs {
		if fd == settings.Fd {
			p.AttachedSocketFDs[i] = p.AttachedSocketFDs[len(p.AttachedSocketFDs)-1]
			p.AttachedSocketFDs = p.AttachedSocketFDs[:len(p.AttachedSocketFDs)-1]
			break
		}
	}

	return nil
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *ProgramSocketFilter) Unpin(relativePath string, deletePin bool) error {
	return p.unpin(relativePath, deletePin)
}
