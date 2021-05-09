package gobpfld

import (
	"fmt"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
)

var _ BPFMap = (*XSKMap)(nil)

// XSKMap is a specialized map type designed to work in conjunction with XSKSocket's.
type XSKMap struct {
	AbstractMap
}

// Get performs a lookup in the xskmap based on the key and returns the file descriptor of the socket
func (m *XSKMap) Get(key int) (int, error) {
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

func (m *XSKMap) Set(key int, value *XSKSocket) error {
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
