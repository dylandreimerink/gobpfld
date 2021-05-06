package gobpfld

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*BPFGenericMap)(nil)

// BPFGenericMap is a runtime reflection implementation for generic BPFTypes.
// Because it uses reflection for type information it is slower than any application specific map.
// For high speed access a custom BPFMap implementation is recommended.
type BPFGenericMap struct {
	AbstractMap
}

func (m *BPFGenericMap) Get(key interface{}, value interface{}) error {
	if !m.Loaded {
		return fmt.Errorf("can't read from an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
	}

	var err error

	attr.Key, err = m.toKeyPtr(key)
	if err != nil {
		return err
	}

	attr.Value_NextKey, err = m.toValuePtr(value)
	if err != nil {
		return err
	}

	err = bpfsys.MapLookupElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

// toBatchKeysPtr checks if 'keys' is a pointer to a array or slice of at least enough elements to hold
// all keys in one batch and that the type of this array has the same memory size as the eBPF map key.
func (m *BPFGenericMap) toBatchKeysPtr(keys interface{}, maxBatchSize uint32) (uintptr, error) {
	keyType := reflect.TypeOf(keys)
	if keyType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("keys argument must be a pointer")
	}

	elem := keyType.Elem()

	switch elem.Kind() {
	case reflect.Array:
		arrayElem := elem.Elem()
		if arrayElem.Size() != uintptr(m.Definition.KeySize) {
			return 0, fmt.Errorf(
				"keys array element type size(%d) doesn't match size of bfp key(%d)",
				arrayElem.Size(),
				m.Definition.KeySize,
			)
		}

		if elem.Len() < int(maxBatchSize) {
			return 0, fmt.Errorf(
				"keys argument must be a pointer to an array or slice containing at least %d elements"+
					" given array only has %d elements",
				maxBatchSize,
				elem.Len(),
			)
		}

		return reflect.ValueOf(elem).Pointer(), nil

	case reflect.Slice:
		sliceElemType := elem.Elem()
		if sliceElemType.Size() != uintptr(m.Definition.KeySize) {
			return 0, fmt.Errorf(
				"keys slice element type size(%d) doesn't match size of bfp key(%d)",
				sliceElemType.Size(),
				m.Definition.KeySize,
			)
		}

		sliceHdr := (*reflect.SliceHeader)(unsafe.Pointer(reflect.ValueOf(keys).Pointer()))
		if sliceHdr.Len < int(maxBatchSize) {
			return 0, fmt.Errorf(
				"keys argument must be a pointer to an array or slice containing at least %d elements"+
					" given slice only has %d elements",
				maxBatchSize,
				sliceHdr.Len,
			)
		}
		return sliceHdr.Data, nil

	default:
		return 0, fmt.Errorf("keys argument must be a pointer to an array or slice")
	}
}

// toBatchValuesPtr checks if 'values' is a pointer to a array or slice of at least enough elements to hold
// all value in one batch and that the type of this array has the same memory size as the eBPF map key.
// If the map type is an per-cpu type the array/slice size is multiplied by the CPU count
func (m *BPFGenericMap) toBatchValuesPtr(values interface{}, maxBatchSize uint32) (uintptr, error) {
	valuesType := reflect.TypeOf(values)
	if valuesType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("values argument must be a pointer")
	}

	elem := valuesType.Elem()

	// If the map type is a per CPU map type we need to multiply the batch size by the CPU count
	// Since per CPU types will return a separate value for each CPU
	if m.isPerCPUMap() {
		maxBatchSize = maxBatchSize * uint32(numCPUs)
	}

	switch elem.Kind() {
	case reflect.Array:
		arrayElem := elem.Elem()
		if arrayElem.Size() != uintptr(m.Definition.ValueSize) {
			return 0, fmt.Errorf(
				"values array element type size(%d) doesn't match size of bfp value(%d)",
				arrayElem.Size(),
				m.Definition.ValueSize,
			)
		}

		if elem.Len() < int(maxBatchSize) {
			return 0, fmt.Errorf(
				"values argument must be a pointer to an array or slice containing at least %d elements"+
					" given array only has %d elements",
				maxBatchSize,
				elem.Len(),
			)
		}

		return reflect.ValueOf(elem).Pointer(), nil

	case reflect.Slice:
		sliceElemType := elem.Elem()
		if sliceElemType.Size() != uintptr(m.Definition.ValueSize) {
			return 0, fmt.Errorf(
				"values slice element type size(%d) doesn't match size of bfp value(%d)",
				sliceElemType.Size(),
				m.Definition.ValueSize,
			)
		}

		sliceHdr := (*reflect.SliceHeader)(unsafe.Pointer(reflect.ValueOf(values).Pointer()))
		if sliceHdr.Len < int(maxBatchSize) {
			return 0, fmt.Errorf(
				"values argument must be a pointer to an array or slice containing at least %d elements"+
					" given slice only has %d elements",
				maxBatchSize,
				sliceHdr.Len,
			)
		}
		return sliceHdr.Data, nil

	default:
		return 0, fmt.Errorf("values argument must be a pointer to an array or slice")
	}
}

// GetBatch fills the keys and values array/slice with the keys and values inside the map up to a maximum of
// maxBatchSize entries. The keys and values array/slice must have at least a length of maxBatchSize.
// The key and value of an entry is has the same index, so for example the value for keys[2] is in values[2].
// Count is the amount of entries returnes, full is true if all entries were returned.
//
// This function is intended for small maps which can be read into userspace all at once since
// GetBatch can only read from the beginning of the map. If the map is to large to read all at once
// a iterator should be used instead of the Get or GetBatch function.
func (m *BPFGenericMap) GetBatch(keys interface{}, values interface{}, maxBatchSize uint32) (count int, full bool, err error) {
	if !m.Loaded {
		return 0, false, fmt.Errorf("can't read from an unloaded map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.Fd,
		OutBatch: uintptr(unsafe.Pointer(&batch)),
		Count:    maxBatchSize,
	}

	attr.Keys, err = m.toBatchKeysPtr(keys, maxBatchSize)
	if err != nil {
		return 0, false, err
	}

	attr.Values, err = m.toBatchValuesPtr(values, maxBatchSize)
	if err != nil {
		return 0, false, err
	}

	err = bpfsys.MapLookupBatch(attr)
	if err != nil {
		// A ENOENT is not an acutal error, the kernel uses it to signal there is no more data after this batch
		if sysErr, ok := err.(*bpfsys.BPFSyscallError); ok && sysErr.Errno == syscall.ENOENT {
			return int(attr.Count), true, nil
		}

		return 0, false, fmt.Errorf("bpf syscall error: %w", err)
	}

	return int(attr.Count), false, nil
}

func (m *BPFGenericMap) Set(key interface{}, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	if !m.Loaded {
		return fmt.Errorf("can't write to an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
		Flags: flags,
	}

	var err error

	attr.Key, err = m.toKeyPtr(key)
	if err != nil {
		return err
	}

	attr.Value_NextKey, err = m.toValuePtr(value)
	if err != nil {
		return err
	}

	err = bpfsys.MapUpdateElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

func (m *BPFGenericMap) SetBatch(
	keys interface{},
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !m.Loaded {
		return 0, fmt.Errorf("can't write to an unloaded map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.Fd,
		OutBatch: uintptr(unsafe.Pointer(&batch)),
		Count:    maxBatchSize,
		Flags:    flags,
		// TODO ElemFlags is only used for the spinlock flag, for which we will add suport later
	}

	attr.Keys, err = m.toBatchKeysPtr(keys, maxBatchSize)
	if err != nil {
		return 0, err
	}

	attr.Values, err = m.toBatchValuesPtr(values, maxBatchSize)
	if err != nil {
		return 0, err
	}

	err = bpfsys.MapUpdateBatch(attr)
	if err != nil {
		return 0, fmt.Errorf("bpf syscall error: %w", err)
	}

	return int(attr.Count), nil
}

func (m *BPFGenericMap) Delete(key interface{}) error {
	if !m.Loaded {
		return fmt.Errorf("can't delete elements in an unloaded map")
	}

	if m.isArrayMap() {
		return fmt.Errorf("can't delete elements from an array type map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
	}

	var err error

	attr.Key, err = m.toKeyPtr(key)
	if err != nil {
		return err
	}

	err = bpfsys.MapDeleteElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

func (m *BPFGenericMap) DeleteBatch(
	keys interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !m.Loaded {
		return 0, fmt.Errorf("can't delete elements in an unloaded map")
	}

	if m.isArrayMap() {
		return 0, fmt.Errorf("can't delete elements from an array type map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.Fd,
		OutBatch: uintptr(unsafe.Pointer(&batch)),
		Count:    maxBatchSize,
	}

	attr.Keys, err = m.toBatchKeysPtr(keys, maxBatchSize)
	if err != nil {
		return 0, err
	}

	err = bpfsys.MapDeleteBatch(attr)
	if err != nil {
		return 0, fmt.Errorf("bpf syscall error: %w", err)
	}

	return int(attr.Count), nil
}

func (m *BPFGenericMap) GetAndDelete(key interface{}, value interface{}) error {
	if !m.Loaded {
		return fmt.Errorf("can't read from an unloaded map")
	}

	if m.isArrayMap() {
		return fmt.Errorf("can't delete elements from an array type map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
	}

	var err error

	attr.Key, err = m.toKeyPtr(key)
	if err != nil {
		return err
	}

	attr.Value_NextKey, err = m.toValuePtr(value)
	if err != nil {
		return err
	}

	err = bpfsys.MapLookupAndDeleteElement(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

func (m *BPFGenericMap) GetAndDeleteBatch(keys interface{}, values interface{}, maxBatchSize uint32) (count int, err error) {
	if !m.Loaded {
		return 0, fmt.Errorf("can't read from an unloaded map")
	}

	if m.isArrayMap() {
		return 0, fmt.Errorf("can't delete elements from an array type map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.Fd,
		OutBatch: uintptr(unsafe.Pointer(&batch)),
		Count:    maxBatchSize,
	}

	attr.Keys, err = m.toBatchKeysPtr(keys, maxBatchSize)
	if err != nil {
		return 0, err
	}

	attr.Values, err = m.toBatchValuesPtr(values, maxBatchSize)
	if err != nil {
		return 0, err
	}

	err = bpfsys.MapLookupBatchAndDelete(attr)
	if err != nil {
		return 0, fmt.Errorf("bpf syscall error: %w", err)
	}

	return int(attr.Count), nil
}

func (m *BPFGenericMap) Iterator() MapIterator {
	// If the kernel has support for batch lookup use the feature
	if kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapLookupBatch) {
		return &BatchLookupIterator{
			BPFMap: m,
		}
	}

	// otherwise fallback to the single lookup iterator

	return &SingleLookupIterator{
		BPFMap: m,
	}
}
