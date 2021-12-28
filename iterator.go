package gobpfld

import (
	"errors"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	bpfSyscall "github.com/dylandreimerink/gobpfld/internal/syscall"
)

// A MapIterator describes an iterator which can iterate over all keys and values of a map without keeping all
// contents in userspace memory at the same time. Since maps can be constantly updated by a eBPF program
// the results are not guaranteed, expect to read duplicate values or not get all keys. This depends greatly
// on the frequency of change of the map, the type of map (arrays are not effected, hashes are) and speed of
// iteration. It is recommended to quickly iterate over maps and not to change them during iteration to reduce
// these effects.
type MapIterator interface {
	// Init should be called with a key and value pointer to variables which will be used on subsequent calls to
	// Next to set values. The key and value pointers must be compatible with the map.
	// The value of key should not be modified between the first call to Next and discarding of the iterator since
	// it is reused. Doing so may cause skipped entries, duplicate entries, or error opon calling Next.
	Init(key, value interface{}) error
	// Next assigns the next value to the key and value last passed via the Init func.
	// True is returned if key and value was updated.
	// If updated is false and err is nil, all values from the iterator were read.
	// On error a iterator should also be considered empty and can be discarded.
	Next() (updated bool, err error)
}

// MapIterForEach fully loops over the given iterator, calling the callback for each entry.
// This offers less control but requires less external setup.
//
// MapIterForEach accepts non-pointer values for key and value in which case they will only be used
// for type information. If callback returns an error the iterator will stop iterating and return the error from
// callback. Callback is always invoked with pointer types, even if non-pointer types were supplied to key and value.
func MapIterForEach(iter MapIterator, key, value interface{}, callback func(key, value interface{}) error) error {
	// If the key is not a pointer
	if reflect.TypeOf(key).Kind() != reflect.Ptr {
		// Create a new value with the same type as 'key' and set 'key' to its pointer
		key = reflect.New(reflect.TypeOf(key)).Interface()
	}

	// / If the value is not a pointer
	if reflect.TypeOf(value).Kind() != reflect.Ptr {
		// Create a new value with the same type as 'value' and set 'value' to its pointer
		value = reflect.New(reflect.TypeOf(value)).Interface()
	}

	err := iter.Init(key, value)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}

	var updated bool
	for {
		updated, err = iter.Next()
		if err != nil || !updated {
			break
		}

		err = callback(key, value)
		if err != nil {
			return fmt.Errorf("callback: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("next: %w", err)
	}

	return nil
}

// ErrIteratorDone indicates that Next has been called on an iterator which is done iterating
var ErrIteratorDone = errors.New("iterator is done")

var _ MapIterator = (*singleLookupIterator)(nil)

// singleLookupIterator uses the MapGetNextKey and MapLookupElem commands to iterate over a map.
// This is very widely supported but not the fastest option.
type singleLookupIterator struct {
	// The map over which to iterate
	BPFMap BPFMap

	// clone of the map so it can't change during iteration
	am    *AbstractMap
	key   uintptr
	value uintptr
	attr  bpfsys.BPFAttrMapElem
	done  bool
}

func (sli *singleLookupIterator) Init(key, value interface{}) error {
	if sli.BPFMap == nil {
		return fmt.Errorf("BPFMap may not be nil")
	}

	// Copy the important features of the map so they are imutable from
	// outside the package during iteration.
	sli.am = &AbstractMap{
		Name:       sli.BPFMap.GetName(),
		loaded:     sli.BPFMap.IsLoaded(),
		fd:         sli.BPFMap.GetFD(),
		Definition: sli.BPFMap.GetDefinition(),
	}

	sli.attr.MapFD = sli.am.fd

	var err error
	sli.key, err = sli.am.toKeyPtr(key)
	if err != nil {
		return fmt.Errorf("toKeyPtr: %w", err)
	}

	sli.value, err = sli.am.toValuePtr(value)
	if err != nil {
		return fmt.Errorf("toValuePtr: %w", err)
	}

	return nil
}

// Next gets the key and value at the current location and writes them to the pointers given to the iterator
// during initialization. It then advances the internal pointer to the next key and value.
// If the iterator can't get the key and value at the current location since we are done iterating or an error
// was encountered 'updated' is false.
func (sli *singleLookupIterator) Next() (updated bool, err error) {
	if sli.am == nil {
		return false, fmt.Errorf("iterator not initialized")
	}

	if sli.done {
		return false, ErrIteratorDone
	}

	sli.attr.Value_NextKey = sli.key

	err = bpfsys.MapGetNextKey(&sli.attr)
	if err != nil {
		sli.done = true
		if sysErr, ok := err.(*bpfSyscall.Error); ok && sysErr.Errno == syscall.ENOENT {
			return false, nil
		}

		return false, err
	}

	sli.attr.Key = sli.attr.Value_NextKey
	sli.attr.Value_NextKey = sli.value

	err = bpfsys.MapLookupElem(&sli.attr)
	if err != nil {
		sli.done = true
		return false, err
	}

	return true, err
}

var _ MapIterator = (*batchLookupIterator)(nil)

type batchLookupIterator struct {
	// The map over which to iterate
	BPFMap BPFMap
	// Size of the buffer, bigger buffers are more cpu efficient but takeup more memory
	BufSize int

	// clone of BPFMap so it can't change during iteration
	am *AbstractMap
	// clone of BufSize so it can't change during iteration
	bufSize int

	// pointer to key
	key reflect.Value
	// pointer to value
	value reflect.Value
	// slice of keys
	keyBuf reflect.Value
	// slice of values
	valueBuf reflect.Value
	inBatch  uint64
	outBatch uint64
	attr     bpfsys.BPFAttrMapBatch

	// Offset into the buffers
	off int
	// Length of the buffer, which may be smaller than bufSize if the kernel
	// returned less then bufSize of entries
	bufLen int

	done    bool
	mapDone bool
}

// According to benchmarks 1024 is a good sweetspot between memory usage and speed
const defaultBufSize = 1024

func (bli *batchLookupIterator) Init(key, value interface{}) error {
	if bli.BPFMap == nil {
		return fmt.Errorf("BPFMap may not be nil")
	}

	bli.bufSize = bli.BufSize
	if bli.bufSize == 0 {
		bli.bufSize = defaultBufSize
	}

	// Copy the important features of the map so they are imutable from
	// outside the package during iteration.
	bli.am = &AbstractMap{
		Name:       bli.BPFMap.GetName(),
		loaded:     bli.BPFMap.IsLoaded(),
		fd:         bli.BPFMap.GetFD(),
		Definition: bli.BPFMap.GetDefinition(),
	}

	keyType := reflect.TypeOf(key)
	if keyType.Kind() != reflect.Ptr {
		return fmt.Errorf("key argument must be a pointer")
	}

	if keyType.Elem().Size() != uintptr(bli.am.Definition.KeySize) {
		return fmt.Errorf(
			"key type size(%d) doesn't match size of bfp key(%d)",
			keyType.Elem().Size(),
			bli.am.Definition.KeySize,
		)
	}

	bli.key = reflect.ValueOf(key)
	bli.keyBuf = reflect.New(reflect.ArrayOf(bli.bufSize, keyType.Elem()))

	valueType := reflect.TypeOf(value)
	if keyType.Kind() != reflect.Ptr {
		return fmt.Errorf("value argument must be a pointer")
	}

	bli.value = reflect.ValueOf(value)
	bli.valueBuf = reflect.New(reflect.ArrayOf(bli.bufSize, valueType.Elem()))

	bli.attr = bpfsys.BPFAttrMapBatch{
		MapFD:    bli.am.fd,
		OutBatch: uintptr(unsafe.Pointer(&bli.outBatch)),
		Keys:     bli.keyBuf.Pointer(),
		Values:   bli.valueBuf.Pointer(),
		Count:    uint32(bli.bufSize),
	}

	return nil
}

// Next gets the key and value at the current location and writes them to the pointers given to the iterator
// during initialization. It then advances the internal pointer to the next key and value.
// If the iterator can't get the key and value at the current location since we are done iterating or an error
// was encountered 'updated' is false.
func (bli *batchLookupIterator) Next() (updated bool, err error) {
	if bli.am == nil {
		return false, fmt.Errorf("iterator not initialized")
	}

	if bli.done {
		return false, ErrIteratorDone
	}

	// If the buffer has never been filled or we have read until the end of the buffer
	if bli.bufLen == 0 || bli.off >= bli.bufLen {
		// If the current buffer was the last the map had to offer
		// and we are done reading that buffer, the iterator is done
		if bli.mapDone {
			bli.done = true
			return false, nil
		}

		err = bpfsys.MapLookupBatch(&bli.attr)
		if err != nil {
			sysErr, ok := err.(*bpfSyscall.Error)
			if !ok || sysErr.Errno != syscall.ENOENT {
				return false, err
			}

			bli.mapDone = true
		}

		// Reset offset since we will start reading from the start of the buffer again
		bli.off = 0
		bli.bufLen = int(bli.attr.Count)

		if bli.bufLen == 0 {
			bli.done = true
			return false, nil
		}

		// Set the address of the in batch, only applicable after the first run
		if bli.attr.InBatch == 0 {
			bli.attr.InBatch = uintptr(unsafe.Pointer(&bli.inBatch))
		}

		bli.inBatch = bli.outBatch
	}

	// Change the underlaying value of 'value' to valueBuf[bli.off]
	bli.value.Elem().Set(bli.valueBuf.Elem().Index(bli.off))
	// Change the underlaying value of 'key' to keyBuf[bli.off]
	bli.key.Elem().Set(bli.keyBuf.Elem().Index(bli.off))

	// Increment the offset
	bli.off++

	return true, nil
}

var _ MapIterator = (*mmappedIterator)(nil)

// mmappedIterator is a special iterator which can loop over mmapped(memory mapped) maps.
// This will use the mmapped memory instread of syscalls which improves performance, but only works on array maps which
// were loaded with the bpftypes.BPFMapFlagsMMapable flag.
type mmappedIterator struct {
	am      *ArrayMap
	nextKey uint32
	key     *uint32
	value   uintptr
}

// Init should be called with a key and value pointer to variables which will be used on subsequent calls to
// Next to set values. The key and value pointers must be compatible with the map.
// The value of key should not be modified between the first call to Next and discarding of the iterator since
// it is reused. Doing so may cause skipped entries, duplicate entries, or error opon calling Next.
func (mmi *mmappedIterator) Init(key, value interface{}) error {
	if mmi.am == nil {
		return fmt.Errorf("array map may not be nil")
	}

	if ikey, ok := key.(*uint32); ok {
		mmi.key = ikey
	} else {
		return fmt.Errorf("key must be an uint32 key")
	}

	mmi.nextKey = 0

	var err error
	mmi.value, err = mmi.am.toValuePtr(value)
	if err != nil {
		return fmt.Errorf("toValuePtr: %w", err)
	}

	return nil
}

// Next assignes the next value to the key and value last passed via the Init func.
// True is returned if key and value was updated.
// If updated is false and err is nil, all values from the iterator were read.
// On error a iterator should also be considered empty and can be discarded.
func (mmi *mmappedIterator) Next() (updated bool, err error) {
	if mmi.am.Definition.MaxEntries == mmi.nextKey {
		// Use next key to double as an 'done' indicator
		mmi.nextKey++
		return false, nil
	}

	if mmi.am.Definition.MaxEntries < mmi.nextKey {
		return false, ErrIteratorDone
	}

	*mmi.key = mmi.nextKey
	mmi.nextKey++

	// We construct a fake slice of bytes with the memory address that was given.
	// We need to do this so we can copy the memory, even if the value isn't an slice type
	dstHdr := reflect.SliceHeader{
		Data: mmi.value,
		Len:  int(mmi.am.Definition.ValueSize),
		Cap:  int(mmi.am.Definition.ValueSize),
	}
	//nolint:govet // should be fine if we make sure len and cap are set correctly and the slice doesn't exit scope
	dstSlice := *(*[]byte)(unsafe.Pointer(&dstHdr))

	start := int(*mmi.key * mmi.am.Definition.ValueSize)
	end := int((*mmi.key + 1) * mmi.am.Definition.ValueSize)
	copy(dstSlice, mmi.am.memoryMapped[start:end])

	return true, nil
}

var _ MapIterator = (*singleMapLookupIterator)(nil)

// singleMapLookupIterator uses the MapGetNextKey and MapLookupElem commands to iterate over a map to get map file
// descriptors. It then uses the MapFromFD function to turn these file descriptors into BPFMap's an assinging them
// to the value pointer. It is a specialized iterator type for array of maps and hash of maps type maps.
type singleMapLookupIterator struct {
	// The map over which to iterate
	BPFMap BPFMap

	// clone of the map so it can't change during iteration
	am    *AbstractMap
	key   uintptr
	value *BPFMap
	id    uint32
	attr  bpfsys.BPFAttrMapElem
	done  bool
}

func (sli *singleMapLookupIterator) Init(key, value interface{}) error {
	if sli.BPFMap == nil {
		return fmt.Errorf("BPFMap may not be nil")
	}

	// Copy the important features of the map so they are imutable from
	// outside the package during iteration.
	sli.am = &AbstractMap{
		Name:       sli.BPFMap.GetName(),
		loaded:     sli.BPFMap.IsLoaded(),
		fd:         sli.BPFMap.GetFD(),
		Definition: sli.BPFMap.GetDefinition(),
	}

	sli.attr.MapFD = sli.am.fd

	var err error
	sli.key, err = sli.am.toKeyPtr(key)
	if err != nil {
		return fmt.Errorf("toKeyPtr: %w", err)
	}

	mPtr, ok := value.(*BPFMap)
	if !ok {
		return fmt.Errorf("value is not of type *BPFMap")
	}
	sli.value = mPtr

	return nil
}

// Next gets the key and value at the current location and writes them to the pointers given to the iterator
// during initialization. It then advances the internal pointer to the next key and value.
// If the iterator can't get the key and value at the current location since we are done iterating or an error
// was encountered 'updated' is false.
func (sli *singleMapLookupIterator) Next() (updated bool, err error) {
	if sli.am == nil {
		return false, fmt.Errorf("iterator not initialized")
	}

	if sli.done {
		return false, ErrIteratorDone
	}

	sli.attr.Value_NextKey = sli.key

	err = bpfsys.MapGetNextKey(&sli.attr)
	if err != nil {
		sli.done = true
		if sysErr, ok := err.(*bpfSyscall.Error); ok && sysErr.Errno == syscall.ENOENT {
			return false, nil
		}

		return false, err
	}

	sli.attr.Key = sli.attr.Value_NextKey
	sli.attr.Value_NextKey = uintptr(unsafe.Pointer(&sli.id))

	err = bpfsys.MapLookupElem(&sli.attr)
	if err != nil {
		sli.done = true
		return false, fmt.Errorf("map lookup elem: %w", err)
	}

	*sli.value, err = MapFromID(sli.id)
	if err != nil {
		sli.done = true
		return false, fmt.Errorf("map from fd: %w", err)
	}

	return true, nil
}

// TODO implement for Queue and Stack maps
// type LookupAndDeleteIterator struct {}
