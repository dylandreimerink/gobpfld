package gobpfld

import (
	"errors"
	"fmt"
	"io"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
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

const defaultBPFVerifierLogSize = 8 * 1024 // 8KB

type BPFProgramLoadSettings struct {
	ProgramType        bpftypes.BPFProgType
	VerifierLogLevel   bpftypes.BPFLogLevel
	VerifierLogSize    int
	ExpectedAttachType bpftypes.BPFAttachType
	IfIndex            uint32
}

func (p *BPFProgram) Load(settings BPFProgramLoadSettings) (log string, err error) {
	// If undefined, use default
	if settings.VerifierLogSize == 0 {
		settings.VerifierLogSize = defaultBPFVerifierLogSize
	}

	verifierLogBytes := make([]byte, settings.VerifierLogSize)

	if settings.ProgramType == bpftypes.BPF_PROG_TYPE_UNSPEC {
		return "", fmt.Errorf("program type unspecified")
	}

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
				spew.Dump(err)
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

	attr := &bpfsys.BPFAttrProgramLoad{
		ProgramType:        settings.ProgramType,
		InsnCnt:            uint32(len(p.Instructions)),
		Insns:              uintptr(unsafe.Pointer(&p.Instructions[0])),
		License:            uintptr(unsafe.Pointer(&licenceCStr)),
		LogLevel:           settings.VerifierLogLevel,
		LogSize:            uint32(settings.VerifierLogSize),
		LogBuf:             uintptr(unsafe.Pointer(&verifierLogBytes[0])),
		ProgName:           p.Name.GetCstr(),
		ExpectedAttachType: settings.ExpectedAttachType,
	}

	p.fd, err = bpfsys.LoadProgram(attr)
	if err != nil {
		return CStrBytesToString(verifierLogBytes), fmt.Errorf("bpf syscall error: %w", err)
	}

	p.loaded = true
	p.programType = settings.ProgramType

	return CStrBytesToString(verifierLogBytes), nil
}

type XDPMode int

const (
	// XDPModeSKB indicates that the XDP program should be loaded driver independent mode.
	// This works for every network driver but is the slowest option, if other loading methods fail this is the fallback
	XDPModeSKB XDPMode = iota
	// XDPModeDRV indicates that the XDP program should be loaded in driver mode.
	// This requires driver support but is faster than SKB mode because it runs at the driver level.
	XDPModeDRV
	// XDPModeHW indicates that the XDP program should be loaded in hardware mode.
	// This requires support from the NIC and driver but is the fastest mode available.
	XDPModeHW
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
}

var (
	ErrProgramNotLoaded            = errors.New("the program is not yet loaded and thus can't be attached")
	ErrProgramNotXDPType           = errors.New("the program is not loaded as an XDP program and thus can't be attached as such")
	ErrNetlinkAlreadyHasXDPProgram = errors.New("the netlink already has an XDP program attached")
)

// XDPLinkAttach attaches a already loaded eBPF XDP program to a network device
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

	err = netlink.LinkSetXdpFdWithFlags(nl, int(p.fd), flags)
	if err != nil {
		return err
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

		// Ignore call and exit "jumps", they don't need labels
		op := inst.Op & 0xF0
		if op == ebpf.BPF_CALL || op == ebpf.BPF_EXIT {
			continue
		}

		// Multiple jumps can reference the same address
		// so check if a label already exists for the target address.
		label := labels[i+int(inst.Off)+1]
		if label == "" {
			// If not, create one
			label = fmt.Sprintf("LBL%d", labelIndex)
			labels[i+int(inst.Off)+1] = label
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
	if len(strBytes) > bpftypes.BPF_OBJ_NAME_LEN {
		return fmt.Errorf("%w: limit is %d bytes, length: %d", ErrObjNameToLarge, bpftypes.BPF_OBJ_NAME_LEN, len(strBytes))
	}

	on.str = string(strBytes)
	for i := 0; i < bpftypes.BPF_OBJ_NAME_LEN; i++ {
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
	if len(strBytes) > bpftypes.BPF_OBJ_NAME_LEN {
		return fmt.Errorf("%w: limit is %d bytes, length: %d", ErrObjNameToLarge, bpftypes.BPF_OBJ_NAME_LEN, len(strBytes))
	}

	on.str = str
	for i := 0; i < bpftypes.BPF_OBJ_NAME_LEN; i++ {
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

// // A BPFInstruction is a BPF virtual machine instruction.
// type BPFInstruction struct {
// 	// Operation to execute.
// 	Op uint8
// 	// The operation register, split into source and destination register
// 	// The upper 4 bits are the destination register, the lower 4 bits the source
// 	Reg uint8
// 	//
// 	Off int16
// 	// Constant parameter. The meaning depends on the Op.
// 	Imm int32
// }

// func (i *BPFInstruction) SetDestReg(v uint8) {
// 	i.Reg = (i.Reg & 0xF0) | (v & 0x0F)
// }

// func (i *BPFInstruction) GetDestReg() uint8 {
// 	return i.Reg & 0x0F
// }

// func (i *BPFInstruction) SetSourceReg(v uint8) {
// 	i.Reg = (i.Reg & 0x0F) | (v << 4 & 0xF0)
// }

// func (i *BPFInstruction) GetSourceReg() uint8 {
// 	return (i.Reg & 0xF0) >> 4
// }

// func (inst *BPFInstruction) String() string {
// 	decoded := "UNKNOWN"

// 	srcR := fmt.Sprintf("r%d", inst.GetSourceReg())
// 	dstR := fmt.Sprintf("r%d", inst.GetDestReg())

// 	// If true, a register is used, otherwise imm
// 	x := inst.Op&0b1000 == 0b1000

// 	switch inst.Op & 0b111 {
// 	case 0x00, 0x01, 0x02, 0x03:
// 		// Is a load instruction, otherwise a store instruction
// 		ld := false
// 		switch inst.Op & 0b111 {
// 		case 0x00:
// 			// Load from non register
// 			ld = true
// 			x = false
// 			decoded = "LD"
// 		case 0x01:
// 			// Load from register
// 			ld = true
// 			x = true
// 			decoded = "LDX"
// 		case 0x02:
// 			// Store to non register
// 			ld = false
// 			x = false
// 			decoded = "ST"
// 		case 0x03:
// 			// Store to register
// 			ld = false
// 			x = true
// 			decoded = "STX"
// 		}

// 		size := ""
// 		switch inst.Op & 0b11000 {
// 		case 0x00:
// 			size = "u32"
// 		case 0x08:
// 			size = "u16"
// 		case 0x10:
// 			size = "u8"
// 		case 0x18:
// 			size = "u64"
// 		}

// 		switch inst.Op & 0b1100000 {
// 		case 0x00:
// 			if ld {
// 				if x {
// 					decoded = fmt.Sprintf("%s = %s", dstR, srcR)
// 				} else {
// 					decoded = fmt.Sprintf("%s = %d", dstR, inst.Imm)
// 				}
// 			} else {
// 				if x {
// 					decoded = fmt.Sprintf("%s = %s", srcR, dstR)
// 				}
// 			}
// 		case 0x20:
// 			decoded += " ABS"
// 		case 0x40:
// 			decoded += " IND"
// 		case 0x60:
// 			decoded += " MEM"

// 			if ld {
// 				if x {
// 					decoded = fmt.Sprintf("%s = *(%s *) (%s + %d)", dstR, size, srcR, inst.Off)
// 				}
// 			} else {
// 				if x {
// 					decoded = fmt.Sprintf("*(%s *) (%s + %d) = %s", size, dstR, inst.Off, srcR)
// 				} else {
// 					decoded = fmt.Sprintf("*(%s *) (%s + %d) = %d", size, dstR, inst.Off, inst.Imm)
// 				}
// 			}

// 		case 0x80:
// 			decoded += " LEN"
// 		case 0xa0:
// 			decoded += " MSH"
// 		case 0xc0:
// 			decoded += " ATOMIC"
// 		}
// 	case 0x04, 0x07:
// 		decoded = "ALU"
// 		switch inst.Op & 0b11110000 {
// 		case 0x00:
// 			decoded = "ADD"
// 			if x {
// 				decoded = fmt.Sprintf("%s += %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s += %d", dstR, inst.Imm)
// 			}
// 		case 0x10:
// 			decoded = "SUB"
// 			if x {
// 				decoded = fmt.Sprintf("%s -= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s -= %d", dstR, inst.Imm)
// 			}
// 		case 0x20:
// 			decoded = "MUL"
// 			if x {
// 				decoded = fmt.Sprintf("%s *= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s *= %d", dstR, inst.Imm)
// 			}
// 		case 0x30:
// 			decoded = "DIV"
// 			if x {
// 				decoded = fmt.Sprintf("%s /= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s /= %d", dstR, inst.Imm)
// 			}
// 		case 0x40:
// 			decoded = "OR"
// 			if x {
// 				decoded = fmt.Sprintf("%s |= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s |= %d", dstR, inst.Imm)
// 			}
// 		case 0x50:
// 			decoded = "AND"
// 			if x {
// 				decoded = fmt.Sprintf("%s &= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s &= %d", dstR, inst.Imm)
// 			}
// 		case 0x60:
// 			decoded = "LSH"
// 			if x {
// 				decoded = fmt.Sprintf("%s << %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s << %d", dstR, inst.Imm)
// 			}
// 		case 0x70:
// 			decoded = "RSH"
// 			if x {
// 				decoded = fmt.Sprintf("%s >> %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s >> %d", dstR, inst.Imm)
// 			}
// 		case 0x80:
// 			decoded = "NEG"
// 			if x {
// 				decoded = fmt.Sprintf("%s = -%s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s = -%d", dstR, inst.Imm)
// 			}
// 		case 0x90:
// 			decoded = "MOD"
// 			if x {
// 				decoded = fmt.Sprintf("%s %%= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s %%= %d", dstR, inst.Imm)
// 			}
// 		case 0xA0:
// 			decoded = "XOR"
// 			if x {
// 				decoded = fmt.Sprintf("%s ^= %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s ^= %d", dstR, inst.Imm)
// 			}
// 		case 0xB0:
// 			decoded = "MOV"
// 			if x {
// 				decoded = fmt.Sprintf("%s = %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s = %d", dstR, inst.Imm)
// 			}
// 		case 0xC0:
// 			decoded = "ARSH"
// 			if x {
// 				decoded = fmt.Sprintf("%s ARSH %s", dstR, srcR)
// 			} else {
// 				decoded = fmt.Sprintf("%s ARSH %d", dstR, inst.Imm)
// 			}
// 		case 0xD0:
// 			decoded = "END"
// 		}
// 	case 0x05, 0x06:
// 		decoded = "JMP"
// 		switch inst.Op & 0b11110000 {
// 		case 0x00:
// 			// Jump always
// 			decoded = fmt.Sprintf("goto pc+%d", inst.Imm)
// 		case 0x10:
// 			decoded = "JEQ"
// 			if x {

// 			} else {
// 				decoded = fmt.Sprintf("if %s == %d goto pc+%d", dstR, inst.Imm, inst.Off)
// 			}
// 		case 0x20:
// 			decoded = "JGT"
// 		case 0x30:
// 			decoded = "JGE"
// 		case 0x40:
// 			decoded = "JSET"
// 		case 0x50:
// 			decoded = "JNE"
// 		case 0x60:
// 			decoded = "JSGT"
// 		case 0x70:
// 			decoded = "JSGE"
// 		case 0x80:
// 			decoded = fmt.Sprintf("call %d", inst.Imm)
// 			funcName, found := BPFHelperFuncNumToStr[inst.Imm]
// 			if found {
// 				decoded = fmt.Sprintf("call %s#%d", funcName, inst.Imm)
// 			}
// 		case 0x90:
// 			decoded = "EXIT"
// 		case 0xA0:
// 			decoded = "JLT"
// 		case 0xB0:
// 			decoded = "JLE"
// 		case 0xC0:
// 			decoded = "JSLT"
// 		case 0xD0:
// 			decoded = "JSLE"
// 		}
// 	}

// 	return fmt.Sprintf("%02X %02X %02X %02X %02X %02X %02X %02X - %s",
// 		inst.Op,
// 		inst.Reg,
// 		inst.Off>>8&0xff,
// 		inst.Off&0xff,
// 		inst.Imm>>24&0xff,
// 		inst.Imm>>16&0xff,
// 		inst.Imm>>8&0xff,
// 		inst.Imm&0xff,
// 		decoded,
// 	)
// }

// var BPFHelperFuncNumToStr = map[int32]string{
// 	1:   "bpf_map_lookup_elem",
// 	2:   "bpf_map_update_elem",
// 	3:   "bpf_map_delete_elem",
// 	4:   "bpf_probe_read",
// 	5:   "bpf_ktime_get_ns",
// 	6:   "bpf_trace_printk",
// 	7:   "bpf_get_prandom_u32",
// 	8:   "bpf_get_smp_processor_id",
// 	9:   "bpf_skb_store_bytes",
// 	10:  "bpf_l3_csum_replace",
// 	11:  "bpf_l4_csum_replace",
// 	12:  "bpf_tail_call",
// 	13:  "bpf_clone_redirect",
// 	14:  "bpf_get_current_pid_tgid",
// 	15:  "bpf_get_current_uid_gid",
// 	16:  "bpf_get_current_comm",
// 	17:  "bpf_get_cgroup_classid",
// 	18:  "bpf_skb_vlan_push",
// 	19:  "bpf_skb_vlan_pop",
// 	20:  "bpf_skb_get_tunnel_key",
// 	21:  "bpf_skb_set_tunnel_key",
// 	22:  "bpf_perf_event_read",
// 	23:  "bpf_redirect",
// 	24:  "bpf_get_route_realm",
// 	25:  "bpf_perf_event_output",
// 	26:  "bpf_skb_load_bytes",
// 	27:  "bpf_get_stackid",
// 	28:  "bpf_csum_diff",
// 	29:  "bpf_skb_get_tunnel_opt",
// 	30:  "bpf_skb_set_tunnel_opt",
// 	31:  "bpf_skb_change_proto",
// 	32:  "bpf_skb_change_type",
// 	33:  "bpf_skb_under_cgroup",
// 	34:  "bpf_get_hash_recalc",
// 	35:  "bpf_get_current_task",
// 	36:  "bpf_probe_write_user",
// 	37:  "bpf_current_task_under_cgroup",
// 	38:  "bpf_skb_change_tail",
// 	39:  "bpf_skb_pull_data",
// 	40:  "bpf_csum_update",
// 	41:  "bpf_set_hash_invalid",
// 	42:  "bpf_get_numa_node_id",
// 	43:  "bpf_skb_change_head",
// 	44:  "bpf_xdp_adjust_head",
// 	45:  "bpf_probe_read_str",
// 	46:  "bpf_get_socket_cookie",
// 	47:  "bpf_get_socket_uid",
// 	48:  "bpf_set_hash",
// 	49:  "bpf_setsockopt",
// 	50:  "bpf_skb_adjust_room",
// 	51:  "bpf_redirect_map",
// 	52:  "bpf_sk_redirect_map",
// 	53:  "bpf_sock_map_update",
// 	54:  "bpf_xdp_adjust_meta",
// 	55:  "bpf_perf_event_read_value",
// 	56:  "bpf_perf_prog_read_value",
// 	57:  "bpf_getsockopt",
// 	58:  "bpf_override_return",
// 	59:  "bpf_sock_ops_cb_flags_set",
// 	60:  "bpf_msg_redirect_map",
// 	61:  "bpf_msg_apply_bytes",
// 	62:  "bpf_msg_cork_bytes",
// 	63:  "bpf_msg_pull_data",
// 	64:  "bpf_bind",
// 	65:  "bpf_xdp_adjust_tail",
// 	66:  "bpf_skb_get_xfrm_state",
// 	67:  "bpf_get_stack",
// 	68:  "bpf_skb_load_bytes_relative",
// 	69:  "bpf_fib_lookup",
// 	70:  "bpf_sock_hash_update",
// 	71:  "bpf_msg_redirect_hash",
// 	72:  "bpf_sk_redirect_hash",
// 	73:  "bpf_lwt_push_encap",
// 	74:  "bpf_lwt_seg6_store_bytes",
// 	75:  "bpf_lwt_seg6_adjust_srh",
// 	76:  "bpf_lwt_seg6_action",
// 	77:  "bpf_rc_repeat",
// 	78:  "bpf_rc_keydown",
// 	79:  "bpf_skb_cgroup_id",
// 	80:  "bpf_get_current_cgroup_id",
// 	81:  "bpf_get_local_storage",
// 	82:  "bpf_sk_select_reuseport",
// 	83:  "bpf_skb_ancestor_cgroup_id",
// 	84:  "bpf_sk_lookup_tcp",
// 	85:  "bpf_sk_lookup_udp",
// 	86:  "bpf_sk_release",
// 	87:  "bpf_map_push_elem",
// 	88:  "bpf_map_pop_elem",
// 	89:  "bpf_map_peek_elem",
// 	90:  "bpf_msg_push_data",
// 	91:  "bpf_msg_pop_data",
// 	92:  "bpf_rc_pointer_rel",
// 	93:  "bpf_spin_lock",
// 	94:  "bpf_spin_unlock",
// 	95:  "bpf_sk_fullsock",
// 	96:  "bpf_tcp_sock",
// 	97:  "bpf_skb_ecn_set_ce",
// 	98:  "bpf_get_listener_sock",
// 	99:  "bpf_skc_lookup_tcp",
// 	100: "bpf_tcp_check_syncookie",
// 	101: "bpf_sysctl_get_name",
// 	102: "bpf_sysctl_get_current_value",
// 	103: "bpf_sysctl_get_new_value",
// 	104: "bpf_sysctl_set_new_value",
// 	105: "bpf_strtol",
// 	106: "bpf_strtoul",
// 	107: "bpf_sk_storage_get",
// 	108: "bpf_sk_storage_delete",
// 	109: "bpf_send_signal",
// 	110: "bpf_tcp_gen_syncookie",
// 	111: "bpf_skb_output",
// 	112: "bpf_probe_read_user",
// 	113: "bpf_probe_read_kernel",
// 	114: "bpf_probe_read_user_str",
// 	115: "bpf_probe_read_kernel_str",
// 	116: "bpf_tcp_send_ack",
// 	117: "bpf_send_signal_thread",
// 	118: "bpf_jiffies64",
// 	119: "bpf_read_branch_records",
// 	120: "bpf_get_ns_current_pid_tgid",
// 	121: "bpf_xdp_output",
// 	122: "bpf_get_netns_cookie",
// 	123: "bpf_get_current_ancestor_cgroup_id",
// 	124: "bpf_sk_assign",
// 	125: "bpf_ktime_get_boot_ns",
// 	126: "bpf_seq_printf",
// 	127: "bpf_seq_write",
// 	128: "bpf_sk_cgroup_id",
// 	129: "bpf_sk_ancestor_cgroup_id",
// 	130: "bpf_ringbuf_output",
// 	131: "bpf_ringbuf_reserve",
// 	132: "bpf_ringbuf_submit",
// 	133: "bpf_ringbuf_discard",
// 	134: "bpf_ringbuf_query",
// 	135: "bpf_csum_level",
// 	136: "bpf_skc_to_tcp6_sock",
// 	137: "bpf_skc_to_tcp_sock",
// 	138: "bpf_skc_to_tcp_timewait_sock",
// 	139: "bpf_skc_to_tcp_request_sock",
// 	140: "bpf_skc_to_udp6_sock",
// 	141: "bpf_get_task_stack",
// 	142: "bpf_load_hdr_opt",
// 	143: "bpf_store_hdr_opt",
// 	144: "bpf_reserve_hdr_opt",
// 	145: "bpf_inode_storage_get",
// 	146: "bpf_inode_storage_delete",
// 	147: "bpf_d_path",
// 	148: "bpf_copy_from_user",
// 	149: "bpf_snprintf_btf",
// 	150: "bpf_seq_printf_btf",
// 	151: "bpf_skb_cgroup_classid",
// 	152: "bpf_redirect_neigh",
// 	153: "bpf_per_cpu_ptr",
// 	154: "bpf_this_cpu_ptr",
// 	155: "bpf_redirect_peer",
// 	156: "bpf_task_storage_get",
// 	157: "bpf_task_storage_delete",
// 	158: "bpf_get_current_task_btf",
// 	159: "bpf_bprm_opts_set",
// 	160: "bpf_ktime_get_coarse_ns",
// 	161: "bpf_ima_inode_hash",
// 	162: "bpf_sock_from_file",
// 	163: "bpf_check_mtu",
// 	164: "bpf_for_each_map_elem",
// }
