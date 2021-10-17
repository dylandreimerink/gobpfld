package gobpfld

import (
	"fmt"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

var _ BPFMap = (*ProgArrayMap)(nil)

// ProgArrayMap is a specialized map type used for tail calls https://docs.cilium.io/en/stable/bpf/#tail-calls
type ProgArrayMap struct {
	AbstractMap
}

func (m *ProgArrayMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_PROG_ARRAY {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_PROG_ARRAY when using an ProgArrayMap")
	}

	return m.load()
}

// Unload closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *ProgArrayMap) Unload() error {
	return m.unload()
}

// Get performs a lookup in the xskmap based on the key and returns the file descriptor of the socket
func (m *ProgArrayMap) Get(key int) (int, error) {
	if !m.Loaded {
		return 0, fmt.Errorf("can't read from an unloaded map")
	}

	var fd int
	attr := &bpfsys.BPFAttrMapElem{
		MapFD:         m.Fd,
		Key:           uintptr(unsafe.Pointer(&key)),
		Value_NextKey: uintptr(unsafe.Pointer(&fd)),
	}

	err := bpfsys.MapLookupElem(attr)
	if err != nil {
		return 0, fmt.Errorf("bpf syscall error: %w", err)
	}

	return fd, nil
}

func (m *ProgArrayMap) Set(key int32, value *BPFProgram) error {
	if !m.Loaded {
		return fmt.Errorf("can't write to an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD:         m.Fd,
		Key:           uintptr(unsafe.Pointer(&key)),
		Value_NextKey: uintptr(unsafe.Pointer(&value.fd)),
	}

	err := bpfsys.MapUpdateElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

// TODO add remaining map functions like Delete and iterator
