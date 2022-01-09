package gobpfld

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/dylandreimerink/gobpfld/internal/cstr"
	bpfSyscall "github.com/dylandreimerink/gobpfld/internal/syscall"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

type AbstractBPFProgram struct {
	// The program type as which it was loaded into the kernel
	ProgramType bpftypes.BPFProgType
	// Name of the program
	Name    ObjName
	License string
	// The actual instructions of the program
	Instructions []ebpf.RawInstruction
	// Locations where map fds need to be inserted into the
	// program before loading
	MapFDLocations map[string][]uint64
	Maps           map[string]BPFMap

	BTF      *BTF
	BTFLines []BTFKernelLine
	BTFFuncs []BTFKernelFunc

	// Indicates if the program is already loaded into the kernel
	loaded bool
	// The file descriptor of the program assigned by the kernel
	fd bpfsys.BPFfd
}

const defaultBPFVerifierLogSize = 1 * 1024 * 1024 // 1MB

func (p *AbstractBPFProgram) Fd() (bpfsys.BPFfd, error) {
	if !p.loaded {
		return 0, fmt.Errorf("program is not loaded")
	}

	return p.fd, nil
}

func (p *AbstractBPFProgram) load(attr bpfsys.BPFAttrProgramLoad) (log string, err error) {
	if p.ProgramType == bpftypes.BPF_PROG_TYPE_UNSPEC {
		return "", fmt.Errorf("program type unspecified")
	}

	// If the given program type is not supported by the current kernel version
	// return a verbose error instead of a syscall error
	kernProgFeat, found := progTypeToKFeature[p.ProgramType]
	// If there is no feature defined for a type, assume it is always supported
	if found {
		if !kernelsupport.CurrentFeatures.Program.Has(kernProgFeat) {
			return "", fmt.Errorf(
				"program type '%s' not supported: %w",
				p.ProgramType,
				bpfsys.ErrNotSupported,
			)
		}
	}

	// TODO validate attach types. In order to use some map types, features or helpers the
	// proper attach type must be specified at program loadtime, we can attempt to detect this
	// requirement based on the linked maps and decompiling the program.

	// TODO validate of used attach type is supported by current kernel version

	// TODO check if helper functions used in program are supported by current kernel version

	licenseCStr := cstr.StringToCStrBytes(p.License)

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

			// BPF_PSEUDO_MAP_FD_VALUE is set if this is an access into a global data section.
			// In this case, imm of the first inst contains the offset which must be moved to the second inst
			if inst.GetSourceReg() == ebpf.BPF_PSEUDO_MAP_FD_VALUE {
				inst2 := &p.Instructions[instIndex+1]
				inst2.Imm = inst.Imm
			} else {
				inst.SetSourceReg(ebpf.BPF_PSEUDO_MAP_FD)
			}

			inst.Imm = int32(bpfMap.GetFD())
		}
	}

	// If we have BTF info and the kernel supports BTF loading
	if p.BTF != nil && kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIBTFLoad) {
		// Load BTF if not already loaded
		if !p.BTF.loaded {
			_, err = p.BTF.Load(BTFLoadOpts{
				LogLevel: bpftypes.BPFLogLevelVerbose,
			})
			if err != nil {
				// TODO make custom error type which includes the verifier log
				return "", fmt.Errorf("load BTF: %w", err)
			}
		}

		attr.ProgBTFFD, err = p.BTF.Fd()
		if err != nil {
			return "", fmt.Errorf("get BTF fd: %w", err)
		}

		if p.BTFLines != nil {
			attr.LineInfo = uintptr(unsafe.Pointer(&p.BTFLines[0]))
			attr.LineInfoCnt = uint32(len(p.BTFLines))
			attr.LineInfoRecSize = uint32(BTFKernelLineSize)
		}

		if p.BTFFuncs != nil {
			attr.FuncInfo = uintptr(unsafe.Pointer(&p.BTFFuncs[0]))
			attr.FuncInfoCnt = uint32(len(p.BTFFuncs))
			attr.FuncInfoRecSize = uint32(BTFKernelFuncSize)
		}
	}

	// If undefined, use default
	if attr.LogSize == 0 {
		attr.LogSize = defaultBPFVerifierLogSize
	}

	verifierLogBytes := make([]byte, attr.LogSize)

	attr.ProgramType = p.ProgramType
	attr.InsnCnt = uint32(len(p.Instructions))
	attr.Insns = uintptr(unsafe.Pointer(&p.Instructions[0]))
	attr.License = uintptr(unsafe.Pointer(&licenseCStr[0]))
	attr.LogBuf = uintptr(unsafe.Pointer(&verifierLogBytes[0]))
	attr.ProgName = p.Name.GetCstr()

	for i := 0; i < 5; i++ {
		p.fd, err = bpfsys.LoadProgram(&attr)
		if err != nil {
			// EAGAIN basically means "there is no data available right now, try again later"
			if sysErr, ok := err.(*bpfSyscall.Error); ok && sysErr.Errno == syscall.EAGAIN {
				continue
			}

			return cstr.BytesToString(verifierLogBytes), fmt.Errorf("bpf syscall error: %w", err)
		}

		// We encountered no error, so stop trying to load the program
		break
	}
	if err != nil {
		return cstr.BytesToString(verifierLogBytes), fmt.Errorf("bpf syscall error: %w", err)
	}

	p.loaded = true

	return cstr.BytesToString(verifierLogBytes), nil
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
func (p *AbstractBPFProgram) Pin(relativePath string) error {
	if !p.loaded {
		return fmt.Errorf("can't pin an unloaded program")
	}

	return PinFD(relativePath, p.fd)
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *AbstractBPFProgram) unpin(relativePath string, deletePin bool) error {
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

	p.loaded = true
	p.ProgramType = progInfo.Type

	return nil
}

// DecodeToReader decodes the eBPF program and writes the human readable format to the provided w.
// The output that is generated is inspired by the llvm-objdump -S output format of eBPF programs
func (p *AbstractBPFProgram) DecodeToReader(w io.Writer) error {
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
