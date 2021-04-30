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
	Licence string
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
}

const defaultBPFVerifierLogSize = 1 * 1024 * 1024 // 1MB

type BPFProgramLoadSettings struct {
	// The type of eBPF program, this determins how the program will be verified and to which
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

func (p *BPFProgram) Load(settings BPFProgramLoadSettings) (log string, err error) {
	if settings.ProgramType == bpftypes.BPF_PROG_TYPE_UNSPEC {
		return "", fmt.Errorf("program type unspecified")
	}

	// If the given program type is not supported by the current kernel version
	// return a verbose error instead of a syscall error
	kProgFeat, found := progTypeToKFeature[settings.ProgramType]
	// If there is no feature defined for a type, assume it is always supported
	if found {
		if !kernelsupport.CurrentFeatures.Program.Has(kProgFeat) {
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

	licenceCStr := StringToCStrBytes(p.Licence)

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

			inst.SetSourceReg(BPFInstSrcRegHashMapFD)
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
		License:            uintptr(unsafe.Pointer(&licenceCStr[0])),
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
	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << iota
	XDP_FLAGS_SKB_MODE
	XDP_FLAGS_DRV_MODE
	XDP_FLAGS_HW_MODE
	XDP_FLAGS_REPLACE
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
	ErrProgramNotLoaded            = errors.New("the program is not yet loaded and thus can't be attached")
	ErrProgramNotXDPType           = errors.New("the program is not loaded as an XDP program and thus can't be attached as such")
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
		flags |= XDP_FLAGS_UPDATE_IF_NOEXIST
	}

	switch settings.XDPMode {
	case XDPModeSKB:
		flags |= XDP_FLAGS_SKB_MODE
	case XDPModeDRV:
		flags |= XDP_FLAGS_DRV_MODE
	case XDPModeHW:
		flags |= XDP_FLAGS_HW_MODE
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
				if flags&XDP_FLAGS_HW_MODE > 0 {
					// Remove hardware flag
					flags = flags ^ XDP_FLAGS_HW_MODE
					// Try driver mode
					flags |= XDP_FLAGS_DRV_MODE

					continue
				}

				// If mode == driver
				if flags&XDP_FLAGS_DRV_MODE > 0 {
					// Remove hardware flag
					flags = flags ^ XDP_FLAGS_DRV_MODE
					// Try SKB mode
					flags |= XDP_FLAGS_SKB_MODE

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
	// Since those are hard to interpert over long distance jumps we add
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
			labelIndex += 1
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

var ErrObjNameToLarge = errors.New("object name to large")

func (on *ObjName) SetBytes(strBytes []byte) error {
	if len(strBytes) > bpftypes.BPF_OBJ_NAME_LEN-1 {
		return fmt.Errorf("%w: limit is %d bytes, length: %d", ErrObjNameToLarge, bpftypes.BPF_OBJ_NAME_LEN-1, len(strBytes))
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
		return fmt.Errorf("%w: limit is %d bytes, length: %d", ErrObjNameToLarge, bpftypes.BPF_OBJ_NAME_LEN-1, len(strBytes))
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

const (
	// If BPFInstSrcRegHashMapFD is the value of a instruction source register, it indicates that the value
	// in K refers to a BPF map file descriptor
	BPFInstSrcRegHashMapFD = 0x01
)
