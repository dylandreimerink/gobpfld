package gobpfld

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func NewBPFProgram() *BPFProgram {
	return &BPFProgram{
		MapFDLocations: make(map[string][]uint64),
		Maps:           make(map[string]BPFMap),
	}
}

type BPFProgram struct {
	// Name of the program
	Name    ObjName
	License string
	// The actual instructions of the program
	Instructions []ebpf.RawInstruction
	// Locations where map fds need to be inserted into the
	// program before loading
	MapFDLocations map[string][]uint64
	Maps           map[string]BPFMap

	// Indicates if the program is already loaded into the kernel
	loaded bool
	// The program type as which it was loaded into the kernel
	programType bpftypes.BPFProgType
	// The file descriptor of the program assigned by the kernel
	fd bpfsys.BPFfd

	// A list of network interface ids the program is linked to
	AttachedNetlinkIDs []int
	AttachedSocketFDs  []int
}

const defaultBPFVerifierLogSize = 1 * 1024 * 1024 // 1MB

type BPFProgramLoadSettings struct {
	// The type of eBPF program, this determines how the program will be verified and to which
	// attach point it can attach.
	ProgramType bpftypes.BPFProgType
	// A hint to the verifier about where you are going to attach the program.
	// This value can be left default for most program types, but must be set for some programs types.
	// This value may restrict where the program may be attached
	ExpectedAttachType bpftypes.BPFAttachType
	// The index of the network interface to which the program will be attached.
	// This is only required for XDP offloading in hardware mode.
	// In hardware mode the kernel needs to know how to convert eBPF into code that can run on the
	// hardware, so at load time it needs to know which devices will be used.
	IfIndex          uint32
	VerifierLogLevel bpftypes.BPFLogLevel
	VerifierLogSize  int
}

func (p *BPFProgram) Fd() (bpfsys.BPFfd, error) {
	if !p.loaded {
		return 0, fmt.Errorf("program is not loaded")
	}

	return p.fd, nil
}

func (p *BPFProgram) Load(settings BPFProgramLoadSettings) (log string, err error) {
	if settings.ProgramType == bpftypes.BPF_PROG_TYPE_UNSPEC {
		return "", fmt.Errorf("program type unspecified")
	}

	// If the given program type is not supported by the current kernel version
	// return a verbose error instead of a syscall error
	kernProgFeat, found := progTypeToKFeature[settings.ProgramType]
	// If there is no feature defined for a type, assume it is always supported
	if found {
		if !kernelsupport.CurrentFeatures.Program.Has(kernProgFeat) {
			return "", fmt.Errorf(
				"program type '%s' not supported: %w",
				settings.ProgramType,
				bpfsys.ErrNotSupported,
			)
		}
	}

	// TODO validate attach types. In order to use some map types, features or helpers the
	// proper attach type must be specified at program loadtime, we can attempt to detect this
	// requirement based on the linked maps and decompiling the program.

	// TODO validate of used attach type is supported by current kernel version

	// TODO check if helper functions used in program are supported by current kernel version

	licenseCStr := StringToCStrBytes(p.License)

	// Rewrite / patch instructions with map fds
	for mapName, offsets := range p.MapFDLocations {
		bpfMap, found := p.Maps[mapName]
		if !found {
			return "", fmt.Errorf("program requires unknown map '%s'", mapName)
		}

		// if the map is not yet loaded, load it now
		if !bpfMap.IsLoaded() {
			err = bpfMap.Load()
			if err != nil {
				return "", fmt.Errorf("error while loading map '%s': %w", mapName, err)
			}
		}

		// For every location the program needs the map fd, insert it
		for _, offset := range offsets {
			instIndex := offset / uint64(ebpf.BPFInstSize)
			inst := &p.Instructions[instIndex]

			inst.SetSourceReg(ebpf.BPF_PSEUDO_MAP_FD)
			inst.Imm = int32(bpfMap.GetFD())
		}
	}

	// If undefined, use default
	if settings.VerifierLogSize == 0 {
		settings.VerifierLogSize = defaultBPFVerifierLogSize
	}

	verifierLogBytes := make([]byte, settings.VerifierLogSize)

	attr := &bpfsys.BPFAttrProgramLoad{
		ProgramType:        settings.ProgramType,
		InsnCnt:            uint32(len(p.Instructions)),
		Insns:              uintptr(unsafe.Pointer(&p.Instructions[0])),
		License:            uintptr(unsafe.Pointer(&licenseCStr[0])),
		LogLevel:           settings.VerifierLogLevel,
		LogSize:            uint32(settings.VerifierLogSize),
		LogBuf:             uintptr(unsafe.Pointer(&verifierLogBytes[0])),
		ProgName:           p.Name.GetCstr(),
		ExpectedAttachType: settings.ExpectedAttachType,
	}

	for i := 0; i < 5; i++ {
		p.fd, err = bpfsys.LoadProgram(attr)
		if err != nil {
			// EAGAIN basically means "there is no data available right now, try again later"
			if sysErr, ok := err.(*bpfsys.BPFSyscallError); ok && sysErr.Errno == syscall.EAGAIN {
				continue
			}

			return CStrBytesToString(verifierLogBytes), fmt.Errorf("bpf syscall error: %w", err)
		}

		// We encountered no error, so stop trying to load the program
		break
	}
	if err != nil {
		return CStrBytesToString(verifierLogBytes), fmt.Errorf("bpf syscall error: %w", err)
	}

	p.loaded = true
	p.programType = settings.ProgramType

	return CStrBytesToString(verifierLogBytes), nil
}

var progTypeToKFeature = map[bpftypes.BPFProgType]kernelsupport.ProgramSupport{
	bpftypes.BPF_PROG_TYPE_SOCKET_FILTER:           kernelsupport.KFeatProgSocketFilter,
	bpftypes.BPF_PROG_TYPE_KPROBE:                  kernelsupport.KFeatProgKProbe,
	bpftypes.BPF_PROG_TYPE_SCHED_CLS:               kernelsupport.KFeatProgSchedCLS,
	bpftypes.BPF_PROG_TYPE_SCHED_ACT:               kernelsupport.KFeatProgSchedACT,
	bpftypes.BPF_PROG_TYPE_TRACEPOINT:              kernelsupport.KFeatProgTracepoint,
	bpftypes.BPF_PROG_TYPE_XDP:                     kernelsupport.KFeatProgXDP,
	bpftypes.BPF_PROG_TYPE_PERF_EVENT:              kernelsupport.KFeatProgPerfEvent,
	bpftypes.BPF_PROG_TYPE_CGROUP_SKB:              kernelsupport.KFeatProgCGroupSKB,
	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK:             kernelsupport.KFeatProgCGroupSocket,
	bpftypes.BPF_PROG_TYPE_LWT_IN:                  kernelsupport.KFeatProgLWTIn,
	bpftypes.BPF_PROG_TYPE_LWT_OUT:                 kernelsupport.KFeatProgLWTOut,
	bpftypes.BPF_PROG_TYPE_LWT_XMIT:                kernelsupport.KFeatProgLWTXmit,
	bpftypes.BPF_PROG_TYPE_SOCK_OPS:                kernelsupport.KFeatProgSocketOps,
	bpftypes.BPF_PROG_TYPE_SK_SKB:                  kernelsupport.KFeatProgSKSKB,
	bpftypes.BPF_PROG_TYPE_CGROUP_DEVICE:           kernelsupport.KFeatProgCGroupDevice,
	bpftypes.BPF_PROG_TYPE_SK_MSG:                  kernelsupport.KFeatProgSKMsg,
	bpftypes.BPF_PROG_TYPE_RAW_TRACEPOINT:          kernelsupport.KFeatProgRawTracepoint,
	bpftypes.BPF_PROG_TYPE_CGROUP_SOCK_ADDR:        kernelsupport.KFeatProgCGroupSocketAddr,
	bpftypes.BPF_PROG_TYPE_LWT_SEG6LOCAL:           kernelsupport.KFeatProgLWTSeg6Local,
	bpftypes.BPF_PROG_TYPE_LIRC_MODE2:              kernelsupport.KFeatProgLIRCMode2,
	bpftypes.BPF_PROG_TYPE_SK_REUSEPORT:            kernelsupport.KFeatProgSKReusePort,
	bpftypes.BPF_PROG_TYPE_FLOW_DISSECTOR:          kernelsupport.KFeatProgFlowDissector,
	bpftypes.BPF_PROG_TYPE_CGROUP_SYSCTL:           kernelsupport.KFeatProgCGroupSysctl,
	bpftypes.BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: kernelsupport.KFeatProgRawTracepointWritable,
	bpftypes.BPF_PROG_TYPE_CGROUP_SOCKOPT:          kernelsupport.KFeatProgCgroupSocketOpt,
	bpftypes.BPF_PROG_TYPE_TRACING:                 kernelsupport.KFeatProgTracing,
	bpftypes.BPF_PROG_TYPE_STRUCT_OPS:              kernelsupport.KFeatProgStructOps,
	bpftypes.BPF_PROG_TYPE_EXT:                     kernelsupport.KFeatProgExt,
	bpftypes.BPF_PROG_TYPE_LSM:                     kernelsupport.KFeatProgLSM,
	bpftypes.BPF_PROG_TYPE_SK_LOOKUP:               kernelsupport.KFeatProgSKLookup,
}

// Pin pins the program to a location in the bpf filesystem, since the file system now also holds a reference
// to the program, the original creator of the program can terminate without triggering the program to be
// closed as well. A program can be unpinned from the bpf FS by another process thus transferring it or persisting
// it across multiple runs of the same program.
func (p *BPFProgram) Pin(relativePath string) error {
	if !p.loaded {
		return fmt.Errorf("can't pin an unloaded program")
	}

	return PinFD(relativePath, p.fd)
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *BPFProgram) Unpin(relativePath string, deletePin bool) error {
	if p.loaded {
		return fmt.Errorf("can't unpin an loaded program")
	}

	var err error
	p.fd, err = UnpinFD(relativePath, deletePin)
	if err != nil {
		return fmt.Errorf("unpin error: %w", err)
	}

	progInfo, err := GetProgramInfo(p.fd)
	if err != nil {
		return fmt.Errorf("get prog info: %w", err)
	}

	p.Name = progInfo.Name

	p.License = "Not GPL compatible"
	if progInfo.Flags&bpftypes.ProgInfoFlagGPLCompatible > 0 {
		// This is technically incorrect, but since there is no way to interrogate the kernel for the exact license
		// this is the only way to ensure that after reloading the program the kernel recognizes the program as
		// GPL compatible.
		p.License = "GPL"
	}

	p.Instructions = progInfo.XlatedProgInsns

	p.Maps = make(map[string]BPFMap, len(progInfo.MapIDs))
	for _, mapID := range progInfo.MapIDs {
		bpfMap, err := MapFromID(mapID)
		if err != nil {
			return fmt.Errorf("map from id: %w", err)
		}
		p.Maps[bpfMap.GetName().str] = bpfMap
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

	p.loaded = true
	p.programType = progInfo.Type

	return nil
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

type BPFProgramXDPLinkAttachSettings struct {
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

// XDPLinkAttach attaches a already loaded eBPF XDP program to a network device. If attaching fails due to the
// XDP mode we will automatically attempt to fallback to slower but better supported XDP mode
func (p *BPFProgram) XDPLinkAttach(settings BPFProgramXDPLinkAttachSettings) error {
	if !p.loaded {
		return ErrProgramNotLoaded
	}

	if p.programType != bpftypes.BPF_PROG_TYPE_XDP {
		return ErrProgramNotXDPType
	}

	nl, err := netlink.LinkByName(settings.InterfaceName)
	if err != nil {
		return err
	}

	flags := 0
	if !settings.Replace {
		//
		flags |= _XDP_FLAGS_UPDATE_IF_NOEXIST
	}

	switch settings.XDPMode {
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
				if settings.DisableFallback {
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
func (p *BPFProgram) XDPLinkDetach(settings BPFProgramXDPLinkDetachSettings) error {
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

// ErrProgramNotSocketFilterType is returned when attempting to attach a non-socket filter program to a socket.
var ErrProgramNotSocketFilterType = errors.New("the program is not loaded as an socket filter program and " +
	"thus can't be attached as such")

// SocketAttachControlFunc attaches a "socket filter" program to a network socket. This function is meant to be used
// as function pointer in net.Dialer.Control or net.ListenConfig.Control.
func (p *BPFProgram) SocketAttachControlFunc(network, address string, c syscall.RawConn) error {
	var err error
	cerr := c.Control(func(fd uintptr) {
		err = p.SocketAttach(fd)
	})
	if err != nil {
		return fmt.Errorf("socket attach: %w", err)
	}
	if cerr != nil {
		return fmt.Errorf("socket attach: %w", cerr)
	}

	return nil
}

// SocketAttach attempts to attach a filter program to the network socket indicated by the given file descriptor.
// This function can be used if network file descriptors are managed outside of the net package or when using
// the net.TCPListener.File function to get a duplicate file descriptor.
func (p *BPFProgram) SocketAttach(fd uintptr) error {
	if !p.loaded {
		return ErrProgramNotLoaded
	}

	if p.programType != bpftypes.BPF_PROG_TYPE_SOCKET_FILTER {
		return ErrProgramNotSocketFilterType
	}

	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, int(p.fd))
	if err != nil {
		return fmt.Errorf("syscall setsockopt: %w", err)
	}

	p.AttachedSocketFDs = append(p.AttachedSocketFDs, int(fd))

	return nil
}

type BPFProgramSocketFilterDetachSettings struct {
	// the file descriptor of the network socket from which the program should be detached
	Fd int
	// If true, the program will be detached from all network interfaces
	All bool
}

// SocketDettach detaches the program from one or all sockets.
func (p *BPFProgram) SocketDettach(settings BPFProgramSocketFilterDetachSettings) error {
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

// DecodeToReader decodes the eBPF program and writes the human readable format to the provided w.
// The output that is generated is inspired by the llvm-objdump -S output format of eBPF programs
func (p *BPFProgram) DecodeToReader(w io.Writer) error {
	decoded, err := ebpf.Decode(p.Instructions)
	if err != nil {
		return fmt.Errorf("error while decoding program: %w", err)
	}

	// The eBPF program has no lables, just offsets within the program.
	// Since those are hard to interpret over long distance jumps we add
	// fake labels called LBLxx, since jumps can occur backwards we will
	// first need to loop over the program to calculate labels and label
	// references.
	labelIndex := 0
	labels := map[int]string{}
	labelRefs := map[int]string{}
	for i, inst := range p.Instructions {
		// We are only interested in the jump class of opcodes
		class := inst.Op & 0b111
		if class != ebpf.BPF_JMP && class != ebpf.BPF_JMP32 {
			continue
		}

		// The offset of the jump
		offset := int(inst.Off)

		op := inst.Op & 0xF0

		// Helper function calls don't need labels, but BPF to BPF calls do
		if op == ebpf.BPF_CALL {
			if inst.GetSourceReg() != ebpf.PSEUDO_CALL {
				continue
			}

			// If we have a BPF to BPF call, the imm is the offset used, not the
			// actual offset of the instruction
			offset = int(inst.Imm)
		}

		// Ignore exit "jumps", they don't need labels
		if op == ebpf.BPF_EXIT {
			continue
		}

		// Multiple jumps can reference the same address
		// so check if a label already exists for the target address.
		label := labels[i+offset+1]
		if label == "" {
			// If not, create one
			label = fmt.Sprintf("LBL%d", labelIndex)
			labels[i+offset+1] = label
			labelIndex++
		}

		labelRefs[i] = label
	}

	for i, inst := range decoded {
		labelRef := labelRefs[i]
		label := labels[i]
		raw := p.Instructions[i]

		// If this address has a label, print it first
		if label != "" {
			fmt.Fprintf(w, "%s:\n", label)
		}

		// print the instruction number with 8 chars padding, should be more than enough
		// since the max program size is 131072 at the moment.
		//
		// Print the raw instruction as hex and then the human readable translation
		fmt.Fprintf(w, "%8d:   %02x %02x %02x %02x %02x %02x %02x %02x   %s",
			i,
			raw.Op,
			raw.Reg,
			(raw.Off>>8)&0xFF,
			raw.Off&0xFF,
			(raw.Imm>>24)&0xFF,
			(raw.Imm>>16)&0xFF,
			(raw.Imm>>8)&0xFF,
			raw.Imm&0xFF,
			inst,
		)

		if labelRef == "" {
			fmt.Fprint(w, "\n")
		} else {
			// If this instruction references another row, append it to the end
			fmt.Fprint(w, " <", labelRef, ">\n")
		}
	}

	return nil
}

type ObjName struct {
	str   string
	cname [bpftypes.BPF_OBJ_NAME_LEN]byte
}

func MustNewObjName(initialName string) ObjName {
	objN, err := NewObjName(initialName)
	if err != nil {
		panic(err)
	}

	return *objN
}

func NewObjName(initialName string) (*ObjName, error) {
	on := &ObjName{}
	return on, on.SetString(initialName)
}

// ErrObjNameToLarge is returned when a given string or byte slice is to large.
// The kernel limits names to 15 usable bytes plus a null-termination char
var ErrObjNameToLarge = errors.New("object name to large")

func (on *ObjName) SetBytes(strBytes []byte) error {
	if len(strBytes) > bpftypes.BPF_OBJ_NAME_LEN-1 {
		return fmt.Errorf(
			"%w: limit is %d bytes, length: %d",
			ErrObjNameToLarge,
			bpftypes.BPF_OBJ_NAME_LEN-1,
			len(strBytes),
		)
	}

	on.str = string(strBytes)
	for i := 0; i < bpftypes.BPF_OBJ_NAME_LEN-1; i++ {
		if len(strBytes) > i {
			on.cname[i] = strBytes[i]
			continue
		}
		on.cname[i] = 0x00
	}

	return nil
}

func (on *ObjName) SetString(str string) error {
	strBytes := []byte(str)
	if len(strBytes) > bpftypes.BPF_OBJ_NAME_LEN-1 {
		return fmt.Errorf(
			"%w: limit is %d bytes, length: %d",
			ErrObjNameToLarge,
			bpftypes.BPF_OBJ_NAME_LEN-1,
			len(strBytes),
		)
	}

	on.str = str
	for i := 0; i < bpftypes.BPF_OBJ_NAME_LEN-1; i++ {
		if len(strBytes) > i {
			on.cname[i] = strBytes[i]
			continue
		}
		on.cname[i] = 0x00
	}

	return nil
}

func (on *ObjName) GetCstr() [bpftypes.BPF_OBJ_NAME_LEN]byte {
	return on.cname
}

func (on *ObjName) String() string {
	return on.str
}
