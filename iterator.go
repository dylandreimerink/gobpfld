package gobpfld

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
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
	// Next assignes the next value to the key and value last passed via the Init func.
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
	for updated, err = iter.Next(); updated && err == nil; updated, err = iter.Next() {
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

var _ MapIterator = (*SingleLookupIterator)(nil)

// SingleLookupIterator uses the MapGetNextKey and MapLookupElem commands to iterate over a map.
// This is very widely supported but not the fastest option.
type SingleLookupIterator struct {
	// The map over which to iterate
	BPFMap BPFMap

	// clone of the map so it can't change during iteration
	am    *AbstractMap
	key   uintptr
	value uintptr
	attr  bpfsys.BPFAttrMapElem
	done  bool
}

func (sli *SingleLookupIterator) Init(key, value interface{}) error {
	if sli.BPFMap == nil {
		return fmt.Errorf("BPFMap may not be nil")
	}

	// Copy the important features of the map so they are imutable from
	// outside the package during iteration.
	sli.am = &AbstractMap{
		Name:       sli.BPFMap.GetName(),
		Loaded:     sli.BPFMap.IsLoaded(),
		Fd:         sli.BPFMap.GetFD(),
		Definition: sli.BPFMap.GetDefinition(),
	}

	sli.attr.MapFD = sli.am.Fd

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

func (sli *SingleLookupIterator) Next() (updated bool, err error) {
	if sli.am == nil {
		return false, fmt.Errorf("iterator not initialized")
	}

	if sli.done {
		return false, fmt.Errorf("iterator is done")
	}

	sli.attr.Value_NextKey = sli.key

	err = bpfsys.MapGetNextKey(&sli.attr)
	if err != nil {
		sli.done = true
		if sysErr, ok := err.(*bpfsys.BPFSyscallError); ok && sysErr.Errno == syscall.ENOENT {
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

var _ MapIterator = (*BatchLookupIterator)(nil)

type BatchLookupIterator struct {
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

func (bli *BatchLookupIterator) Init(key, value interface{}) error {
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
		Loaded:     bli.BPFMap.IsLoaded(),
		Fd:         bli.BPFMap.GetFD(),
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

	if valueType.Elem().Size() != uintptr(bli.am.Definition.ValueSize) {
		return fmt.Errorf(
			"value type size(%d) doesn't match size of bfp value(%d)",
			valueType.Elem().Size(),
			bli.am.Definition.ValueSize,
		)
	}

	bli.value = reflect.ValueOf(value)
	bli.valueBuf = reflect.New(reflect.ArrayOf(bli.bufSize, valueType.Elem()))

	bli.attr = bpfsys.BPFAttrMapBatch{
		MapFD:    bli.am.Fd,
		InBatch:  uintptr(unsafe.Pointer(&bli.inBatch)),
		OutBatch: uintptr(unsafe.Pointer(&bli.outBatch)),
		Keys:     bli.keyBuf.Pointer(),
		Values:   bli.valueBuf.Pointer(),
		Count:    uint32(bli.bufSize),
	}

	return nil
}

func (bli *BatchLookupIterator) Next() (updated bool, err error) {
	if bli.am == nil {
		return false, fmt.Errorf("iterator not initialized")
	}

	if bli.done {
		return false, fmt.Errorf("iterator is done")
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
			sysErr, ok := err.(*bpfsys.BPFSyscallError)
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

// TODO implement for Queue and Stack maps
// type LookupAndDeleteIterator struct {}
