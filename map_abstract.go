package gobpfld

import (
	"fmt"
	"reflect"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	bpfSyscall "github.com/dylandreimerink/gobpfld/internal/syscall"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

// AbstractMap is a base struct which implements BPFMap however it lacks any features for interacting
// with the map, these need to be implemented by a specific map type which can embed this type to reduce
// code dupplication. This type is exported so users of the library can also embed this struct in application
// specific implementation.
type AbstractMap struct {
	// The name of map. This value is passed to the kernel, it is limited to 15 characters. Its use is limited
	// and mostly to aid diagnostic tools which inspect the BPF subsystem. For primary identification the ID or FD
	// should be used.
	Name ObjName
	// Definition describes the properties of this map
	Definition BPFMapDef
	// A reference to the BTF which contains the type of this map.
	BTF *BTF
	// The type of the map.
	BTFMapType BTFType

	// definition is an unexported copy of Definition which will be pinned as soon as the map is loaded
	// to prevent the user from chaning the definition while the map is loaded.
	definition BPFMapDef
	loaded     bool
	fd         bpfsys.BPFfd
}

// Load validates and loads the userspace map definition into the kernel.
func (m *AbstractMap) load(changeAttr func(attr *bpfsys.BPFAttrMapCreate)) error {
	err := m.Definition.Validate()
	if err != nil {
		return err
	}

	attr := &bpfsys.BPFAttrMapCreate{
		MapType:    m.Definition.Type,
		KeySize:    m.Definition.KeySize,
		ValueSize:  m.Definition.ValueSize,
		MaxEntries: m.Definition.MaxEntries,
		MapFlags:   m.Definition.Flags,
	}

	if kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapName) {
		attr.MapName = m.Name.GetCstr()
	}

	// If BTF info is available and the current kernel supports it
	if m.BTF != nil && m.BTFMapType != nil && kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIBTFLoad) {
		// Load BTF if not already loaded
		if !m.BTF.loaded {
			var log string
			log, err = m.BTF.Load(BTFLoadOpts{
				LogLevel: bpftypes.BPFLogLevelVerbose,
			})
			if err != nil {
				return fmt.Errorf("load BTF: %w\nLog: %s", err, log)
			}
		}

		btfFd, err := m.BTF.Fd()
		if err != nil {
			return fmt.Errorf("get BTF fd: %w", err)
		}

		attr.BTFFD = btfFd

		// TODO we need to provide the typeID of the key an value type. But the bpf_map_def struct only has the
		// key and value sizes. Libbpf has helpers to define maps, they most likey use these helpers to reference
		// the key and value types. So we need to add support for the libbpf defined helpers, and communicate
		// to the user that they need to use these helpers to get type info.
		// NOTE side note, we might be able to generate type info from the loader program, should be an alternative
		// since it requires providing type information before loading the maps.
	}

	if changeAttr != nil {
		changeAttr(attr)
	}

	m.fd, err = bpfsys.MapCreate(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	// Copy exported definition to internal definition so it we always have a copy of the loaded definition which
	// the user can't change while loaded.
	m.definition = m.Definition
	m.loaded = true

	return nil
}

// Unload closes the file descriptor associate with the map, this will cause the map to close from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *AbstractMap) close() error {
	err := m.fd.Close()
	if err != nil {
		return fmt.Errorf("error while closing fd: %w", err)
	}

	m.fd = 0
	m.loaded = false

	return nil
}

// Pin pins the map to a location in the bpf filesystem, since the file system now also holds a reference
// to the map the original creator of the map can terminate without triggering the map to be closed as well.
// A map can be unpinned from the bpf FS by another process thus transferring it or persisting it across
// multiple runs of the same program.
func (m *AbstractMap) Pin(relativePath string) error {
	if !m.loaded {
		return fmt.Errorf("can't pin an unloaded map")
	}

	return PinFD(relativePath, m.fd)
}

// Unpin captures the file descriptor of the map at the given 'relativePath' from the kernel.
// The definition in this map must match the definition of the pinned map, otherwise this function
// will return an error since mismatched definitions might cause seemingly unrelated bugs in other functions.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the map, thus transferring
// ownership of the map in a scenario where the map is not shared between multiple programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (m *AbstractMap) Unpin(relativePath string, deletePin bool) error {
	if m.loaded {
		return fmt.Errorf("can't unpin a map since it is already loaded")
	}

	var err error
	m.fd, err = UnpinFD(relativePath, deletePin)
	if err != nil {
		return fmt.Errorf("unpin error: %w", err)
	}

	pinnedMapDef := BPFMapDef{}
	err = bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   m.fd,
		Info:    uintptr(unsafe.Pointer(&pinnedMapDef)),
		InfoLen: uint32(bpfMapDefSize),
	})
	if err != nil {
		return fmt.Errorf("bpf obj get info by fd syscall error: %w", err)
	}

	// Since other functions use the definition for userspace checks we need to make sure
	// that the map def in the kernel is the same a the one in userspace.
	// The other approach would be to just match the userspace definition to the one in the kernel
	// but if this AbstractMap is embedded in a specialized map and we unpin a generic map by accident
	// it could result in strange bugs, so this is more fool proof but less user automatic.
	// Map types embedding the AbstractType should define their own constructor functions which can
	// make a map from a pinned map path.
	if m.Definition.Equal(pinnedMapDef) {
		// Getting the map from the FS created a new file descriptor. Close it so the kernel knows we will
		// not be using it. If we leak the FD the map will never close.
		fdErr := m.fd.Close()
		if fdErr != nil {
			return fmt.Errorf("pinned map definition doesn't match definition of current map, "+
				"new fd wasn't closed: %w", err)
		}

		return fmt.Errorf("pinned map definition doesn't match definition of current map")
	}

	// Copy exported definition to internal definition so it we always have a copy of the loaded definition which
	// the user can't change while loaded.
	m.definition = m.Definition
	m.loaded = true

	return nil
}

func (m *AbstractMap) IsLoaded() bool {
	return m.loaded
}

func (m *AbstractMap) GetName() ObjName {
	return m.Name
}

func (m *AbstractMap) GetFD() bpfsys.BPFfd {
	return m.fd
}

func (m *AbstractMap) GetDefinition() BPFMapDef {
	// If the map is loaded we will return the internal version of definition since we know it will not be modified
	// to avoid misuse of the library
	if m.loaded {
		return m.definition
	}

	return m.Definition
}

// get uses reflection to to dynamically get a k/v pair from any map as long as the sizes of the key and value match
// the map definition.
func (m *AbstractMap) get(key interface{}, value interface{}) error {
	if !m.loaded {
		return fmt.Errorf("can't read from an unloaded map")
	}

	// Return a human readable error since the kernel will not allow us to read from the map anyway
	if m.Definition.Flags&bpftypes.BPFMapFlagsWriteOnly != 0 {
		return fmt.Errorf("can't read from map since the 'write only' flag is set")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.fd,
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

// toKeyPtr checks if 'key' is a pointer to a type which has the same
// size in memory as the key of the eBPF map.
func (m *AbstractMap) toKeyPtr(key interface{}) (uintptr, error) {
	keyType := reflect.TypeOf(key)
	if keyType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("key argument must be a pointer")
	}

	if keyType.Elem().Size() != uintptr(m.Definition.KeySize) {
		return 0, fmt.Errorf(
			"key type size(%d) doesn't match size of bpf key(%d)",
			keyType.Elem().Size(),
			m.Definition.KeySize,
		)
	}

	return reflect.ValueOf(key).Pointer(), nil
}

// toValuePtr checks if 'value' is a pointer to a type which has the same
// size in memory as the value of the eBPF map.
func (m *AbstractMap) toValuePtr(value interface{}) (uintptr, error) {
	valueType := reflect.TypeOf(value)
	if valueType.Kind() != reflect.Ptr {
		return 0, fmt.Errorf("value argument must be a pointer")
	}

	elem := valueType.Elem()

	// If the map type is a per CPU map, the value must be an array
	// or slice with at least as much elements as the system has CPU cores
	if m.isPerCPUMap() {
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

// getBatch fills the keys and values array/slice with the keys and values inside the map up to a maximum of
// maxBatchSize entries. The keys and values array/slice must have at least a length of maxBatchSize.
// The key and value of an entry is has the same index, so for example the value for keys[2] is in values[2].
// Count is the amount of entries returns, partial is true if not all elements of keys and values could be set.
//
// This function is intended for small maps which can be read into userspace all at once since
// getBatch can only read from the beginning of the map. If the map is to large to read all at once
// a iterator should be used instead of the get or getBatch function.
func (m *AbstractMap) getBatch(
	keys interface{},
	values interface{},
	maxBatchSize uint32,
) (
	count int,
	partial bool,
	err error,
) {
	if !m.loaded {
		return 0, false, fmt.Errorf("can't read from an unloaded map")
	}

	// Return a human readable error since the kernel will not allow us to read from the map anyway
	if m.Definition.Flags&bpftypes.BPFMapFlagsWriteOnly != 0 {
		return 0, false, fmt.Errorf("can't read from map since the 'write only' flag is set")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.fd,
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
		if sysErr, ok := err.(*bpfSyscall.Error); ok && sysErr.Errno == syscall.ENOENT {
			return int(attr.Count), true, nil
		}

		return 0, false, fmt.Errorf("bpf syscall error: %w", err)
	}

	return int(attr.Count), false, nil
}

func (m *AbstractMap) set(key interface{}, value interface{}, flags bpfsys.BPFAttrMapElemFlags) error {
	if !m.loaded {
		return fmt.Errorf("can't write to an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.fd,
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

func (m *AbstractMap) setBatch(
	keys interface{},
	values interface{},
	flags bpfsys.BPFAttrMapElemFlags,
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !m.loaded {
		return 0, fmt.Errorf("can't write to an unloaded map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.fd,
		OutBatch: uintptr(unsafe.Pointer(&batch)),
		Count:    maxBatchSize,
		Flags:    flags,
		// TODO ElemFlags is only used for the spinlock flag, for which we will add support later
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

func (m *AbstractMap) delete(key interface{}) error {
	if !m.loaded {
		return fmt.Errorf("can't delete elements in an unloaded map")
	}

	if m.isArrayMap() {
		return fmt.Errorf("can't delete elements from an array type map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.fd,
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

func (m *AbstractMap) deleteBatch(
	keys interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !m.loaded {
		return 0, fmt.Errorf("can't delete elements in an unloaded map")
	}

	if m.isArrayMap() {
		return 0, fmt.Errorf("can't delete elements from an array type map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.fd,
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

func (m *AbstractMap) getAndDelete(key interface{}, value interface{}) error {
	if !m.loaded {
		return fmt.Errorf("can't read from an unloaded map")
	}

	if m.isArrayMap() {
		return fmt.Errorf("can't delete elements from an array type map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.fd,
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

func (m *AbstractMap) getAndDeleteBatch(
	keys interface{},
	values interface{},
	maxBatchSize uint32,
) (
	count int,
	err error,
) {
	if !m.loaded {
		return 0, fmt.Errorf("can't read from an unloaded map")
	}

	if m.isArrayMap() {
		return 0, fmt.Errorf("can't delete elements from an array type map")
	}

	var batch uint64
	attr := &bpfsys.BPFAttrMapBatch{
		MapFD:    m.fd,
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

// toBatchKeysPtr checks if 'keys' is a pointer to a array or slice of at least enough elements to hold
// all keys in one batch and that the type of this array has the same memory size as the eBPF map key.
func (m *AbstractMap) toBatchKeysPtr(keys interface{}, maxBatchSize uint32) (uintptr, error) {
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
func (m *AbstractMap) toBatchValuesPtr(values interface{}, maxBatchSize uint32) (uintptr, error) {
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

var numCPUs = runtime.NumCPU()

func (m *AbstractMap) isPerCPUMap() bool {
	return m.Definition.Type == bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY ||
		m.Definition.Type == bpftypes.BPF_MAP_TYPE_PERCPU_HASH ||
		m.Definition.Type == bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH
}

func (m *AbstractMap) isArrayMap() bool {
	return m.Definition.Type == bpftypes.BPF_MAP_TYPE_ARRAY ||
		m.Definition.Type == bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY
}
