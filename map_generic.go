package gobpfld

import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

var _ BPFMap = (*BPFGenericMap)(nil)

// BPFGenericMap is a runtime reflection implementation for generic BPFTypes.
// Because it uses reflection for type information it is slower than any application specific map.
// For high speed access a custom BPFMap implementation is recommended.
type BPFGenericMap struct {
	AbstractMap
}

// toValuePtr checks if 'key' is a pointer to a type which has the same
// size in memory as the key of the eBPF map.
func (m *BPFGenericMap) toKeyPtr(key interface{}) (uintptr, error) {
	keyType := reflect.TypeOf(key)
	if keyType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("key argument must be a pointer")
	}

	if keyType.Elem().Size() != uintptr(m.Definition.KeySize) {
		return 0, fmt.Errorf(
			"key type size(%d) doesn't match size of bfp key(%d)",
			keyType.Elem().Size(),
			m.Definition.KeySize,
		)
	}

	return reflect.ValueOf(key).Pointer(), nil
}

var numCPUs = runtime.NumCPU()

// toValuePtr checks if 'value' is a pointer to a type which has the same
// size in memory as the value of the eBPF map.
func (m *BPFGenericMap) toValuePtr(value interface{}) (uintptr, error) {
	valueType := reflect.TypeOf(value)
	if valueType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("value argument must be a pointer")
	}

	elem := valueType.Elem()

	// If the map type is a per CPU map, the value must be an array
	// or slice with at least as much elements as the system has CPU cores
	if m.Definition.Type == bpftypes.BPF_MAP_TYPE_PERCPU_HASH ||
		m.Definition.Type == bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY {

		switch elem.Kind() {
		case reflect.Array:
			arrayElem := elem.Elem()
			if arrayElem.Size() != uintptr(m.Definition.ValueSize) {
				return 0, fmt.Errorf(
					"value array element type size(%d) doesn't match size of bfp value(%d)",
					arrayElem.Size(),
					m.Definition.ValueSize,
				)
			}

			if elem.Len() < numCPUs {
				return 0, fmt.Errorf(
					"value argument must be a pointer to an array or slice containing at least %d elements"+
						" given array only has %d elements",
					numCPUs,
					elem.Len(),
				)
			}

			return reflect.ValueOf(value).Pointer(), nil

		case reflect.Slice:
			sliceElemType := elem.Elem()
			if sliceElemType.Size() != uintptr(m.Definition.ValueSize) {
				return 0, fmt.Errorf(
					"value slice element type size(%d) doesn't match size of bfp value(%d)",
					sliceElemType.Size(),
					m.Definition.ValueSize,
				)
			}

			sliceHdr := (*reflect.SliceHeader)(unsafe.Pointer(reflect.ValueOf(value).Pointer()))
			if sliceHdr.Len < numCPUs {
				return 0, fmt.Errorf(
					"value argument must be a pointer to an array or slice containing at least %d elements"+
						" given slice only has %d elements",
					numCPUs,
					sliceHdr.Len,
				)
			}
			return sliceHdr.Data, nil

		default:
			return 0, fmt.Errorf(
				"value argument must be a pointer to an array or slice containing at least %d elements",
				numCPUs,
			)
		}
	}

	if elem.Size() != uintptr(m.Definition.ValueSize) {
		return 0, fmt.Errorf(
			"value type size(%d) doesn't match size of bfp value(%d)",
			elem.Size(),
			m.Definition.ValueSize,
		)
	}

	return reflect.ValueOf(value).Pointer(), nil
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

	attr.Value_NextKey, err = m.toValuePtr(key)
	if err != nil {
		return err
	}

	err = bpfsys.MapUpdateElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}
