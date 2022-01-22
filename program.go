package gobpfld

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

func NewBPFProgram(progType bpftypes.BPFProgType) BPFProgram {
	ap := NewAbstractBPFProgram()
	ap.ProgramType = progType
	return BPFProgramFromAbstract(ap)
}

func NewAbstractBPFProgram() AbstractBPFProgram {
	return AbstractBPFProgram{
		MapFDLocations: make(map[string][]uint64),
		Maps:           make(map[string]BPFMap),
	}
}

func BPFProgramFromAbstract(abstract AbstractBPFProgram) BPFProgram {
	switch abstract.ProgramType {
	case bpftypes.BPF_PROG_TYPE_XDP:
		return &ProgramXDP{
			AbstractBPFProgram: abstract,
		}

	case bpftypes.BPF_PROG_TYPE_SOCKET_FILTER:
		return &ProgramSocketFilter{
			AbstractBPFProgram: abstract,
		}

	case bpftypes.BPF_PROG_TYPE_TRACEPOINT:
		return &ProgramTracepoint{
			AbstractBPFProgram: abstract,
		}

	case bpftypes.BPF_PROG_TYPE_KPROBE:
		return &ProgramKProbe{
			AbstractBPFProgram: abstract,
		}

	default:
		panic("unsupported program type")
	}
}

type BPFProgram interface {
	Fd() (bpfsys.BPFfd, error)
	Pin(relativePath string) error
	Unpin(relativePath string, deletePin bool) error
	GetAbstractProgram() AbstractBPFProgram
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

// https://elixir.bootlin.com/linux/v5.12.10/source/kernel/bpf/syscall.c#L719
var objNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_\.]{1,15}$`)

func (on *ObjName) SetString(str string) error {
	if len(str) > 15 {
		return ErrObjNameToLarge
	}

	if !objNameRegexp.MatchString(str) {
		return fmt.Errorf("object name must be 1 to 15 alpha numeric, '_', or '.' chars")
	}

	strBytes := []byte(str)
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
