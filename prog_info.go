package gobpfld

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	bpfSyscall "github.com/dylandreimerink/gobpfld/internal/syscall"
)

// BPFProgInfo is a more easy to use version of the bpftypes.BPFProgInfo
// the main difference being that this struct contains the actual from the kernel
// not just pointers to them
type BPFProgInfo struct {
	Type            bpftypes.BPFProgType
	ID              uint32
	Tag             [bpftypes.BPF_TAG_SIZE]byte
	JitedProgInsns  []ebpf.RawInstruction
	XlatedProgInsns []ebpf.RawInstruction
	LoadTime        time.Time
	CreatedByUID    uint32
	MapIDs          []uint32
	Name            ObjName
	IfIndex         uint32
	Flags           bpftypes.BPFProgInfoFlags
	NetNSDev        uint64
	NetNSIno        uint64
	JitedKsyms      []uint64
	JitedFuncLens   []uint32
	BTFID           uint32
	FuncInfo        []bpftypes.BPFFuncInfo
	LineInfo        []bpftypes.BPFLineInfo
	JitedLineInfo   []bpftypes.BPFLineInfo
	ProgTags        [][bpftypes.BPF_TAG_SIZE]byte
	RunTimeNs       uint64
	RunCnt          uint64
	RecursionMisses uint64
}

// GetLoadedPrograms returns a slice of info object about all loaded bpf programs
func GetLoadedPrograms() ([]BPFProgInfo, error) {
	programs := []BPFProgInfo{}

	attr := &bpfsys.BPFAttrGetID{}
	for {
		err := bpfsys.ProgramGetNextID(attr)
		if syserr, ok := err.(*bpfSyscall.Error); ok {
			// if the "next" id could not be found, we have scanned them all
			if syserr.Errno == syscall.ENOENT {
				return programs, nil
			}

			return nil, fmt.Errorf("bpf prog_get_next_id returned error: %w", syserr)
		}

		fd, syserr := bpfsys.ProgramGetFDByID(&bpfsys.BPFAttrGetID{
			ID: attr.NextID,
		})
		if syserr != nil {
			return nil, fmt.Errorf("bpf prog_get_fd_by_id returned error: %w", syserr)
		}

		progInfo, err := GetProgramInfo(fd)
		if err != nil {
			return nil, fmt.Errorf("get program info: %w", syserr)
		}

		programs = append(programs, *progInfo)

		attr.ID = attr.NextID
	}
}

func getSystemBootTime() (time.Time, error) {
	procUptime, err := os.Open("/proc/uptime")
	if err != nil {
		return time.Time{}, fmt.Errorf("can't open /proc/uptime which we need to calculate the program loadtime")
	}

	uptimeBytes, err := ioutil.ReadAll(procUptime)
	if err != nil {
		return time.Time{}, fmt.Errorf("can't read /proc/uptime which we need to calculate the program loadtime")
	}

	uptimeString := string(uptimeBytes)
	uptimeString = uptimeString[:strings.Index(uptimeString, " ")]
	uptimeString = "-" + strings.ReplaceAll(uptimeString, ".", "s") + "0ms"
	uptime, err := time.ParseDuration(uptimeString)
	if err != nil {
		return time.Time{}, err
	}

	return time.Now().Add(uptime), nil
}

var systemBootTime *time.Time

func GetProgramInfo(fd bpfsys.BPFfd) (*BPFProgInfo, error) {
	if systemBootTime == nil {
		bt, err := getSystemBootTime()
		if err != nil {
			return nil, fmt.Errorf("get system time: %w", err)
		}

		systemBootTime = &bt
	}

	// At first we will call the function without passing any buffers since we don't know the
	// sizes to allocate yet
	info := bpftypes.BPFProgInfo{}
	err := bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   fd,
		InfoLen: uint32(bpftypes.BPFProgInfoSize),
		Info:    uintptr(unsafe.Pointer(&info)),
	})
	if err != nil {
		return nil, fmt.Errorf("bpf obj_get_info_by_fd returned error: %w", err)
	}

	progInfo := BPFProgInfo{
		Type:            info.Type,
		ID:              info.ID,
		Tag:             info.Tag,
		JitedProgInsns:  make([]ebpf.RawInstruction, info.JitedProgLen/uint32(ebpf.BPFInstSize)),
		XlatedProgInsns: make([]ebpf.RawInstruction, info.XlatedProgLen/uint32(ebpf.BPFInstSize)),
		LoadTime:        systemBootTime.Add(time.Duration(info.LoadTime)),
		CreatedByUID:    info.CreatedByUID,
		MapIDs:          make([]uint32, info.NumMapIDs),
		Name: ObjName{
			str:   string(info.Name[:]),
			cname: info.Name,
		},
		IfIndex:         info.IfIndex,
		Flags:           info.Flags,
		NetNSDev:        info.NetNSDev,
		NetNSIno:        info.NetNSIno,
		JitedKsyms:      make([]uint64, info.NumJitedKSyms),    // TODO make custom type for ksyms
		JitedFuncLens:   make([]uint32, info.NumJitedFuncLens), // TODO make custom type for func lens
		BTFID:           info.BTFID,
		FuncInfo:        make([]bpftypes.BPFFuncInfo, info.NumFuncInfo),
		LineInfo:        make([]bpftypes.BPFLineInfo, info.NumLineInfo),
		JitedLineInfo:   make([]bpftypes.BPFLineInfo, info.NumJitedLineInfo),
		ProgTags:        make([][8]byte, info.NumProgTags),
		RunTimeNs:       info.RunTimeNs,
		RunCnt:          info.RunCnt,
		RecursionMisses: info.RecursionMisses,
	}

	if len(progInfo.JitedProgInsns) > 0 {
		info.JitedProgInsns = uintptr(unsafe.Pointer(&progInfo.JitedProgInsns[0]))
	}

	if len(progInfo.XlatedProgInsns) > 0 {
		info.XlatedProgInsns = uintptr(unsafe.Pointer(&progInfo.XlatedProgInsns[0]))
	}

	if len(progInfo.MapIDs) > 0 {
		info.MapIDs = uintptr(unsafe.Pointer(&progInfo.MapIDs[0]))
	}

	if len(progInfo.JitedKsyms) > 0 {
		info.JitedKsyms = uintptr(unsafe.Pointer(&progInfo.JitedKsyms[0]))
	}

	if len(progInfo.JitedFuncLens) > 0 {
		info.JitedFuncLens = uintptr(unsafe.Pointer(&progInfo.JitedFuncLens[0]))
	}

	if len(progInfo.FuncInfo) > 0 {
		info.FuncInfo = uintptr(unsafe.Pointer(&progInfo.FuncInfo[0]))
	}

	if len(progInfo.LineInfo) > 0 {
		info.LineInfo = uintptr(unsafe.Pointer(&progInfo.LineInfo[0]))
	}

	if len(progInfo.JitedLineInfo) > 0 {
		info.JitedLineInfo = uintptr(unsafe.Pointer(&progInfo.JitedLineInfo[0]))
	}

	progTags := make([]byte, info.NumProgTags*bpftypes.BPF_TAG_SIZE)
	if len(progTags) > 0 {
		info.ProgTags = uintptr(unsafe.Pointer(&progTags[0]))
	}

	err = bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   fd,
		InfoLen: uint32(bpftypes.BPFProgInfoSize),
		Info:    uintptr(unsafe.Pointer(&info)),
	})
	if err != nil {
		return nil, fmt.Errorf("bpf obj_get_info_by_fd returned error: %w", err)
	}

	for i := 0; i < len(progTags); i += bpftypes.BPF_TAG_SIZE {
		copy(progInfo.ProgTags[i/bpftypes.BPF_TAG_SIZE][:], progTags[i:i+bpftypes.BPF_TAG_SIZE])
	}

	return &progInfo, nil
}
