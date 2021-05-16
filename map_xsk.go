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

	// we record the pointers to the XSKSockets seperatly since the kernel doesn't
	// allow us to 'get' from the map after setting values
	userspaceMap map[uint32]*XSKSocket
}

func (m *XSKMap) Load() error {
	m.userspaceMap = make(map[uint32]*XSKSocket)

	return m.AbstractMap.Load()
}

// Get performs a lookup in the xskmap based on the key and returns the file descriptor of the socket
func (m *XSKMap) Get(key uint32) (*XSKSocket, error) {
	if !m.Loaded {
		return nil, fmt.Errorf("can't read from an unloaded map")
	}

	return m.userspaceMap[key], nil
}

func (m *XSKMap) Set(key uint32, value *XSKSocket) error {
	if !m.Loaded {
		return fmt.Errorf("can't write to an unloaded map")
	}

	if value == nil {
		return fmt.Errorf("can't write a nil socket to the map")
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

	m.userspaceMap[key] = value

	return nil
}

func (m *XSKMap) Delete(key uint32) error {
	if !m.Loaded {
		return fmt.Errorf("can't delete elements in an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
		Key:   uintptr(unsafe.Pointer(&key)),
	}

	err := bpfsys.MapDeleteElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	delete(m.userspaceMap, key)

	return nil
}

func (m *XSKMap) Iterator() MapIterator {
	return &XSKIterator{
		xskMap: m,
	}
}

type XSKIterator struct {
	xskMap *XSKMap

	key   *uint32
	value **XSKSocket

	keyArray []uint32
	index    int

	done bool
}

func (xi *XSKIterator) Init(key, value interface{}) error {
	var ok bool
	xi.key, ok = key.(*uint32)
	if !ok {
		return fmt.Errorf("key must be a pointer to a uint32")
	}

	xi.value, ok = value.(**XSKSocket)
	if !ok {
		return fmt.Errorf("key must be a double pointer to a gobpfld.XSKSocket")
	}

	for key := range xi.xskMap.userspaceMap {
		xi.keyArray = append(xi.keyArray, key)
	}

	return nil
}

// TODO change iterator so we do use the next_key syscall but lookup the value using the userspace map
func (xi *XSKIterator) Next() (updated bool, err error) {
	if xi.done {
		return false, fmt.Errorf("iterator is done")
	}

	if len(xi.keyArray) == 0 {
		xi.done = true
		return false, nil
	}

	if xi.index >= len(xi.keyArray) {
		xi.done = true
		return false, nil
	}

	key := xi.keyArray[uint32(xi.index)]
	value := xi.xskMap.userspaceMap[key]

	*xi.key = key
	*xi.value = value

	xi.index++

	return true, nil
}
