package gobpfld

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/vishvananda/netlink"
)

var _ BPFProgram = (*ProgramXDP)(nil)

type ProgramXDP struct {
	AbstractBPFProgram

	// A list of network interface ids the program is linked to
	AttachedNetlinkIDs []int
}

type ProgXDPLoadOpts struct {
	// A hint to the verifier about where you are going to attach the program.
	// This value can be left default for most program types, but must be set for some programs types.
	// This value may restrict where the program may be attached
	ExpectedAttachType bpftypes.BPFAttachType
	// The index of the network interface to which the program will be attached.
	// This option is only required for XDP offloading in hardware mode.
	// In hardware mode the kernel needs to know how to convert eBPF into code that can run on the
	// hardware, so at load time it needs to know which devices will be used.
	IfIndex          uint32
	VerifierLogLevel bpftypes.BPFLogLevel
	VerifierLogSize  int
}

func (p *ProgramXDP) Load(opts ProgXDPLoadOpts) (log string, err error) {
	switch opts.ExpectedAttachType {
	case bpftypes.BPF_XDP,
		bpftypes.BPF_XDP_CPUMAP,
		bpftypes.BPF_XDP_DEVMAP:
		break
	case 0:
		// 0/unspecified is allowed since one only has to specify an attach type when using a link, cpu redirect or
		// device redirect.
		break
	default:
		return "", fmt.Errorf(
			"expected attach type invalid, must be on of 0/unspecified, BPF_XDP, BPF_XDP_CPUMAP, or BPF_XDP_DEVMAP",
		)
	}

	return p.load(bpfsys.BPFAttrProgramLoad{
		LogLevel:           opts.VerifierLogLevel,
		LogSize:            uint32(opts.VerifierLogSize),
		ExpectedAttachType: opts.ExpectedAttachType,
		ProgIFIndex:        opts.IfIndex,
	})
}

type XDPMode int

const (
	// XDPModeHW indicates that the XDP program should be loaded in hardware mode.
	// This requires support from the NIC and driver but is the fastest mode available.
	XDPModeHW XDPMode = iota
	// XDPModeDRV indicates that the XDP program should be loaded in driver mode.
	// This requires driver support but is faster than SKB mode because it runs at the driver level.
	XDPModeDRV
	// XDPModeSKB indicates that the XDP program should be loaded driver independent mode.
	// This works for every network driver but is the slowest option, if other loading methods fail this is the fallback
	XDPModeSKB
)

type ProgXDPAttachOpts struct {
	// Name of the network interface to which to attach the XDP program
	InterfaceName string
	// If true, this program will replace any existing program.
	// If false, attempting to attach a program while one is still loaded will cause an error
	Replace bool
	XDPMode XDPMode
	// If true, we will return a error when we can't attach the program in the specified mode
	// If false, we will automatically fallback to a less specific XPDMode if the current mode fails.
	DisableFallback bool
}

var (
	// ErrProgramNotLoaded is returned when attempting to attach a non-loaded program
	ErrProgramNotLoaded = errors.New("the program is not yet loaded and thus can't be attached")
	// ErrProgramNotXDPType is returned when attempting to attach a non-XDP program to a netdev
	ErrProgramNotXDPType = errors.New("the program is not loaded as an XDP program and thus can't be " +
		"attached as such")
	// ErrNetlinkAlreadyHasXDPProgram is returned when attempting to attach a program to an
	// netdev that already has an XDP program attached
	ErrNetlinkAlreadyHasXDPProgram = errors.New("the netlink already has an XDP program attached")
)

// Attach attaches a already loaded eBPF XDP program to a network device. If attaching fails due to the
// XDP mode we will automatically attempt to fallback to slower but better supported XDP mode
func (p *ProgramXDP) Attach(opts ProgXDPAttachOpts) error {
	if !p.loaded {
		return ErrProgramNotLoaded
	}

	if p.ProgramType != bpftypes.BPF_PROG_TYPE_XDP {
		return ErrProgramNotXDPType
	}

	nl, err := netlink.LinkByName(opts.InterfaceName)
	if err != nil {
		return err
	}

	const (
		// If set asks the netlink to only attach the program if there is non at the moment.
		// If unset, the existing XDP program will be replaced
		_XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << iota
		_XDP_FLAGS_SKB_MODE
		_XDP_FLAGS_DRV_MODE
		_XDP_FLAGS_HW_MODE
		// TODO add support for explicit program replacement https://www.spinics.net/lists/netdev/msg640357.html
		_XDP_FLAGS_REPLACE //nolint:deadcode,varcheck // reserved for future use
	)

	flags := 0
	if !opts.Replace {
		//
		flags |= _XDP_FLAGS_UPDATE_IF_NOEXIST
	}

	switch opts.XDPMode {
	case XDPModeSKB:
		flags |= _XDP_FLAGS_SKB_MODE
	case XDPModeDRV:
		flags |= _XDP_FLAGS_DRV_MODE
	case XDPModeHW:
		flags |= _XDP_FLAGS_HW_MODE
	}

	for i := 0; i < 3; i++ {
		err = netlink.LinkSetXdpFdWithFlags(nl, int(p.fd), flags)
		if err != nil {
			// If we got at ENOTSUP(95) - Operation not supported error
			if sysErr, ok := err.(syscall.Errno); ok && sysErr == syscall.ENOTSUP {
				// If fallback is disabled, just error
				if opts.DisableFallback {
					return err
				}

				// If mode == hardware
				if flags&_XDP_FLAGS_HW_MODE > 0 {
					// Remove hardware flag
					flags = flags ^ _XDP_FLAGS_HW_MODE
					// Try driver mode
					flags |= _XDP_FLAGS_DRV_MODE

					continue
				}

				// If mode == driver
				if flags&_XDP_FLAGS_DRV_MODE > 0 {
					// Remove hardware flag
					flags = flags ^ _XDP_FLAGS_DRV_MODE
					// Try SKB mode
					flags |= _XDP_FLAGS_SKB_MODE

					continue
				}

				// If already in SKB mode and we still error, nothing we can do.
			}
			return err
		}

		// We did not error, so break
		break
	}

	p.AttachedNetlinkIDs = append(p.AttachedNetlinkIDs, nl.Attrs().Index)

	return nil
}

type BPFProgramXDPLinkDetachSettings struct {
	// Name of the network interface from which the program should detach
	InterfaceName string
	// If true, the program will be detached from all network interfaces
	All bool
}

// XDPLinkDetach detaches a XDP program from one or all network interfaces it is attached to.
func (p *ProgramXDP) XDPLinkDetach(settings BPFProgramXDPLinkDetachSettings) error {
	if settings.All {
		for _, ifidx := range p.AttachedNetlinkIDs {
			nl, err := netlink.LinkByIndex(ifidx)
			// ignore not found errors, if the interface no longer exists the program is also detached
			if err != nil && err.Error() != "Link not found" {
				return err
			}

			err = netlink.LinkSetXdpFd(nl, -1)
			if err != nil {
				return err
			}
		}

		p.AttachedNetlinkIDs = nil
		return nil
	}

	nl, err := netlink.LinkByName(settings.InterfaceName)
	if err != nil {
		return err
	}

	err = netlink.LinkSetXdpFd(nl, -1)
	if err != nil {
		return err
	}

	for i, ifidx := range p.AttachedNetlinkIDs {
		if ifidx == nl.Attrs().Index {
			p.AttachedNetlinkIDs[i] = p.AttachedNetlinkIDs[len(p.AttachedNetlinkIDs)-1]
			p.AttachedNetlinkIDs = p.AttachedNetlinkIDs[:len(p.AttachedNetlinkIDs)-1]
			break
		}
	}

	return nil
}

// TestXDPProgSettings are the settings passed to XDPTestProgram
type TestXDPProgSettings struct {
	// How often should the test be repeated? For benchmarking purposes
	Repeat uint32
	// The input data, in this case the ethernet frame to check
	Data []byte
}

// TestXDPProgResult is the result of XDPTestProgram
type TestXDPProgResult struct {
	// The return value of the program
	ReturnValue int32
	// The avarage duration of a single run in nanoseconds
	Duration uint32
	// The modified data (as it would be received by the network stack)
	Data []byte
}

// XDPTestProgram executes a loaded XDP program on supplied data. This feature can be used to test the functionality
// of an XDP program without having to generate actual traffic on an interface. It is also useful for benchmarking
// a XDP programs which is otherwise impractical.
func (p *ProgramXDP) XDPTestProgram(settings TestXDPProgSettings) (*TestXDPProgResult, error) {
	if !p.loaded {
		return nil, ErrProgramNotLoaded
	}

	if p.ProgramType != bpftypes.BPF_PROG_TYPE_XDP {
		return nil, ErrProgramNotXDPType
	}

	// Some basic checks on the inputs to generate nice errors
	// https://elixir.bootlin.com/linux/v5.12.10/source/net/bpf/test_run.c#L181

	const ethHeaderLength = 14
	if len(settings.Data) < ethHeaderLength {
		return nil, fmt.Errorf("data must be at least %d bytes (size of a ethernet frame header)", ethHeaderLength)
	}

	pageSize := os.Getpagesize()

	const xdpHeadspace = 256
	if len(settings.Data)+xdpHeadspace > pageSize {
		return nil, fmt.Errorf(
			"data size '%d' + %d bytes headroom is larger than the page size on this machine: '%d'",
			ethHeaderLength,
			xdpHeadspace,
			pageSize,
		)
	}

	// Allocate an array the size of a single page since that should be the limit for any generated data
	out := make([]byte, pageSize)

	attr := bpfsys.BPFAttrProgTestRun{
		ProgFD:      p.fd,
		Repeat:      settings.Repeat,
		DataSizeIn:  uint32(len(settings.Data)),
		DataIn:      uintptr(unsafe.Pointer(&settings.Data[0])),
		DataSizeOut: uint32(pageSize),
		DataOut:     uintptr(unsafe.Pointer(&out[0])),
	}

	if err := bpfsys.ProgramTestRun(&attr); err != nil {
		return nil, fmt.Errorf("bpf syscall error: %w", err)
	}

	return &TestXDPProgResult{
		ReturnValue: int32(attr.Retval),
		Duration:    attr.Duration,
		Data:        out[:attr.DataSizeOut],
	}, nil
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *ProgramXDP) Unpin(relativePath string, deletePin bool) error {
	progInfo, err := GetProgramInfo(p.fd)
	if err != nil {
		return fmt.Errorf("get prog info: %w", err)
	}

	err = p.unpin(relativePath, deletePin)
	if err != nil {
		return fmt.Errorf("unpin: %w", err)
	}

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("get link list: %w", err)
	}
	for _, link := range links {
		attr := link.Attrs()

		if attr.Xdp.ProgId == progInfo.ID {
			p.AttachedNetlinkIDs = append(p.AttachedNetlinkIDs, attr.Index)
		}
	}

	return nil
}
