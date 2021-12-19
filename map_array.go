package gobpfld

import (
	"fmt"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
	"golang.org/x/sys/unix"
)

var _ BPFMap = (*ArrayMap)(nil)

// ArrayMap is a map which has a integer key from 0 to MaxEntries. It is a generic map type so the value can be any
// type.
type ArrayMap struct {
	AbstractMap

	memoryMapped []byte
}

func (m *ArrayMap) Load() error {
	if m.Definition.Type != bpftypes.BPF_MAP_TYPE_ARRAY {
		return fmt.Errorf("map type in definition must be BPF_MAP_TYPE_ARRAY when using an ArrayMap")
	}

	err := m.load()
	if err != nil {
		return fmt.Errorf("error while loading map: %w", err)
	}

	err = mapRegister.add(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	// From bpf_map_mmap_sz in libbpf
	valueSize := m.Definition.ValueSize
	if valueSize < 8 {
		valueSize = 8
	}
	mmapLen := int(valueSize * m.Definition.MaxEntries)
	pz := os.Getpagesize()
	if mmapLen < pz {
		mmapLen = pz
	}

	// If the mmapable flag is set
	if m.Definition.Flags&bpftypes.BPFMapFlagsMMapable != 0 {
		// This first mmap allocates memory which is not yet mapped to the BPF map yet.
		m.memoryMapped, err = syscall.Mmap(
			-1,
			0,
			mmapLen,
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED|unix.MAP_ANONYMOUS,
		)
		if err != nil {
			return fmt.Errorf("mmap array map: %w", err)
		}

		// Set mmap prot based on the map flags
		prot := unix.PROT_READ | unix.PROT_WRITE
		if m.Definition.Flags&bpftypes.BPFMapFlagsWriteOnly != 0 {
			prot = unix.PROT_WRITE
		}
		if m.Definition.Flags&bpftypes.BPFMapFlagsReadOnly != 0 {
			prot = unix.PROT_READ
		}

		// Remap the same byteslice but this time attach it to the FD of the BPF map/
		// I don't really know why this needs to be done in 2 steps, setting the FD in the first mmap doesn't work.
		// Since libbpf does it like this, and it works, we will keep it.
		_, err = mmap(
			(*reflect.SliceHeader)(unsafe.Pointer(&m.memoryMapped)).Data,
			uintptr(len(m.memoryMapped)),
			prot,
			unix.MAP_SHARED|unix.MAP_FIXED,
			int(m.fd),
			0,
		)
		if err != nil {
			return fmt.Errorf("mmap array map: %w", err)
		}
	}

	return nil
}

// Close closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *ArrayMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	if m.memoryMapped != nil {
		err := syscall.Munmap(m.memoryMapped)
		if err != nil {
			return fmt.Errorf("error while munmapping array memory: %w", err)
		}

		m.memoryMapped = nil
	}

	return m.close()
}

func (m *ArrayMap) Get(key uint32, value interface{}) error {
	// If the map is not mmapped we need to use regular syscall's to get the value
	if m.memoryMapped == nil {
		return m.get(&key, value)
	}

	// In this case, we the map is mmapped so we can just access the memory without syscalls.

	if key >= m.Definition.MaxEntries {
		return fmt.Errorf("key is outside of map bounds")
	}

	destAddr, err := m.toValuePtr(value)
	if err != nil {
		return err
	}

	// We construct a fake slice of bytes with the memory address that was given.
	// We need to do this so we can copy the memory, even if the value isn't an slice type
	dstHdr := reflect.SliceHeader{
		Data: destAddr,
		Len:  int(m.Definition.ValueSize),
		Cap:  int(m.Definition.ValueSize),
	}
	//nolint:govet // should be fine if we make sure len and cap are set correctly and the slice doesn't exit scope
	dstSlice := *(*[]byte)(unsafe.Pointer(&dstHdr))

	start := int(key * m.Definition.ValueSize)
	end := int((key + 1) * m.Definition.ValueSize)
	copy(dstSlice, m.memoryMapped[start:end])

	return nil
}

// GetBatch fills the keys slice and values array/slice with the keys and values inside the map.
// The keys slice and values array/slice must have the same length. The key and value of an entry is has the same
// index, so for example the value for keys[2] is in values[2]. Count is the amount of entries returns,
// partial is true if not all elements of keys and values could be set.
//
// This function is intended for small maps which can be read into userspace all at once since
// GetBatch can only read from the beginning of the map. If the map is to large to read all at once
// a iterator should be used instead of the Get or GetBatch function.
func (m *ArrayMap) GetBatch(
	keys []uint32,
	values interface{},
) (
	count int,
	partial bool,
	err error,
) {
	keysLen := len(keys)

	// Very unlikely, but we have to check
	if keysLen > maxUint32 {
		return 0, false, fmt.Errorf("max len of 'keys' allowed is %d", maxUint32)
	}

	// If the map is not mmapped we need to use regular syscall's to get the values
	if m.memoryMapped == nil {
		return m.getBatch(&keys, values, uint32(keysLen))
	}

	// In this case, we the map is mmapped so we can just access the memory without syscalls.

	dstAddr, err := m.toBatchValuesPtr(values, uint32(keysLen))
	if err != nil {
		return 0, false, err
	}

	valueSize := int(m.Definition.ValueSize)

	// We construct a fake slice of bytes with the memory address that was given.
	// We need to do this so we can copy the memory, even if the value isn't an slice type
	dstHdr := reflect.SliceHeader{
		Data: dstAddr,
		Len:  valueSize * keysLen,
		Cap:  valueSize * keysLen,
	}
	//nolint:govet // should be fine if we make sure len and cap are set correctly and the slice doesn't exit scope
	dstSlice := *(*[]byte)(unsafe.Pointer(&dstHdr))

	// Set keys to the indexes
	for i := 0; i < keysLen; i++ {
		keys[i] = uint32(i)
	}

	// Copy until dstSlice is full or we have read the whole map
	bytesCopied := copy(dstSlice, m.memoryMapped[:int(m.Definition.MaxEntries)*valueSize])

	return bytesCopied / valueSize, (bytesCopied / valueSize) < keysLen, nil
}

func (m *ArrayMap) Set(key uint32, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	// If the map is not mmapped we need to use regular syscall's to set the value
	if m.memoryMapped == nil {
		return m.set(&key, value, flags)
	}

	// In this case, we the map is mmapped so we can just access the memory without syscalls.

	if key >= m.Definition.MaxEntries {
		return fmt.Errorf("key is outside of map bounds")
	}

	srcAddr, err := m.toValuePtr(value)
	if err != nil {
		return err
	}

	// We construct a fake slice of bytes with the memory address that was given.
	// We need to do this so we can copy the memory, even if the value isn't an slice type
	srcHdr := reflect.SliceHeader{
		Data: srcAddr,
		Len:  int(m.Definition.ValueSize),
		Cap:  int(m.Definition.ValueSize),
	}
	//nolint:govet // should be fine if we make sure len and cap are set correctly and the slice doesn't exit scope
	srcSlice := *(*[]byte)(unsafe.Pointer(&srcHdr))

	start := int(key * m.Definition.ValueSize)
	end := int((key + 1) * m.Definition.ValueSize)
	copy(m.memoryMapped[start:end], srcSlice)

	return nil
}

func (m *ArrayMap) SetBatch(
	keys []uint32,
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
) (
	count int,
	err error,
) {
	keysLen := len(keys)

	// Very unlikely, but we have to check
	if keysLen > maxUint32 {
		return 0, fmt.Errorf("max len of 'keys' allowed is %d", maxUint32)
	}

	// If the map is not mmapped we need to use regular syscall's to set the values
	if m.memoryMapped == nil {
		return m.setBatch(&keys, values, flags, uint32(keysLen))
	}

	// In this case, we the map is mmapped so we can just access the memory without syscalls.

	srcAddr, err := m.toBatchValuesPtr(values, uint32(keysLen))
	if err != nil {
		return 0, err
	}

	valueSize := int(m.Definition.ValueSize)

	// We construct a fake slice of bytes with the memory address that was given.
	// We need to do this so we can copy the memory, even if the value isn't an slice type
	srcHdr := reflect.SliceHeader{
		Data: srcAddr,
		Len:  valueSize * keysLen,
		Cap:  valueSize * keysLen,
	}
	//nolint:govet // should be fine if we make sure len and cap are set correctly and the slice doesn't exit scope
	srcSlice := *(*[]byte)(unsafe.Pointer(&srcHdr))

	for i, key := range keys {
		// Out of bounds key will cause panics when trying to get that offset in the slice
		if key >= m.Definition.MaxEntries {
			return i, fmt.Errorf("key index is out of bounds, max key: %d", m.Definition.MaxEntries-1)
		}

		mmStart := int(key) * valueSize
		mmEnd := int(key+1) * valueSize
		srcStart := i * valueSize
		srcEnd := (i + 1) * valueSize
		copy(m.memoryMapped[mmStart:mmEnd], srcSlice[srcStart:srcEnd])
	}

	return keysLen, nil
}

func (m *ArrayMap) Iterator() MapIterator {
	// If the array map is mmapped, using the MMappedIterator is the fastest option
	if m.memoryMapped != nil {
		return &mmappedIterator{
			am: m,
		}
	}

	// If the kernel doesn't have support for batch lookup, use single lookup
	if !kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBatchOps) {
		return &singleLookupIterator{
			BPFMap: m,
		}
	}

	// If there is no reason not to use the batch lookup iterator, use it
	return &batchLookupIterator{
		BPFMap: m,
	}
}
