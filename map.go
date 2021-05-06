package gobpfld

import (
	"fmt"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

type BPFMap interface {
	GetName() ObjName
	GetFD() bpfsys.BPFfd
	IsLoaded() bool
	GetDefinition() BPFMapDef

	Load() error
}

// MapFromID creates a BPFMap object from a map that is already loaded into the kernel.
func MapFromID(id uint32) (BPFMap, error) {
	fd, err := bpfsys.MapGetFDByID(&bpfsys.BPFAttrGetID{
		ID: id,
	})
	if err != nil {
		return nil, fmt.Errorf("bpf syscall error: %w", err)
	}

	mapInfo := bpftypes.BPFMapInfo{}
	err = bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   fd,
		Info:    uintptr(unsafe.Pointer(&mapInfo)),
		InfoLen: uint32(bpftypes.BPFMapInfoSize),
	})
	if err != nil {
		return nil, fmt.Errorf("bpf obj get info by fd syscall error: %w", err)
	}

	return &BPFGenericMap{
		AbstractMap: AbstractMap{
			Name: ObjName{
				cname: mapInfo.Name,
				str:   CStrBytesToString(mapInfo.Name[:]),
			},
			Loaded: true,
			Fd:     fd,
			Definition: BPFMapDef{
				Type:       mapInfo.Type,
				KeySize:    mapInfo.KeySize,
				ValueSize:  mapInfo.ValueSize,
				MaxEntries: mapInfo.MaxEntries,
				Flags:      bpftypes.BPFMapFlags(mapInfo.MapFlags),
			},
		},
	}, nil
}

// AbstractMap is a base struct which implements BPFMap however it lacks any features for interacting
// with the map, these need to be implemented by a specific map type which can embed this type to reduce
// code dupplication. This type is exported so users of the library can also embed this struct in application
// specific implementation.
type AbstractMap struct {
	Name ObjName

	Loaded bool
	Fd     bpfsys.BPFfd

	Definition BPFMapDef
}

// Load validates and loads the userspace map definition into the kernel.
func (m *AbstractMap) Load() error {
	err := m.Definition.Validate()
	if err != nil {
		return err
	}

	attr := &bpfsys.BPFAttrMapCreate{
		MapName:    m.Name.GetCstr(),
		MapType:    m.Definition.Type,
		KeySize:    m.Definition.KeySize,
		ValueSize:  m.Definition.ValueSize,
		MaxEntries: m.Definition.MaxEntries,
		MapFlags:   m.Definition.Flags,
	}

	m.Fd, err = bpfsys.MapCreate(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	m.Loaded = true

	return nil
}

// Unload closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *AbstractMap) Unload() error {
	err := m.Fd.Close()
	if err != nil {
		return fmt.Errorf("error while closing fd: %w", err)
	}

	m.Fd = 0
	m.Loaded = false

	return nil
}

// Pin pins the map to a location in the bpf filesystem, since the file system now also holds a reference
// to the map the original creator of the map can terminate without triggering the map to be closed as well.
// A map can be unpinned from the bpf FS by another process thus transfering it or persisting it across
// multiple runs of the same program.
func (m *AbstractMap) Pin(relativePath string) error {
	if !m.Loaded {
		return fmt.Errorf("can't pin an unloaded map")
	}

	return PinFD(relativePath, m.Fd)
}

// Unpin captures the file descriptor of the map at the given 'relativePath' from the kernel.
// The definition in this map must match the definition of the pinned map, otherwise this function
// will return an error since mismatched definitions might cause seemingly unrelated bugs in other functions.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the map, thus transfering
// ownership of the map in a scenario where the map is not shared between multiple programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (m *AbstractMap) Unpin(relativePath string, deletePin bool) error {
	if m.Loaded {
		return fmt.Errorf("can't unpin a map since it is already loaded")
	}

	var err error
	m.Fd, err = UnpinFD(relativePath, deletePin)
	if err != nil {
		return fmt.Errorf("unpin error: %w", err)
	}

	pinnedMapDef := BPFMapDef{}
	err = bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   m.Fd,
		Info:    uintptr(unsafe.Pointer(&pinnedMapDef)),
		InfoLen: uint32(BPFMapDefSize),
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
		fdErr := m.Fd.Close()
		if fdErr != nil {
			return fmt.Errorf("pinned map definition doesn't match definition of current map, new fd wasn't closed: %w", err)
		}

		return fmt.Errorf("pinned map definition doesn't match definition of current map")
	}

	m.Loaded = true

	return nil
}

func (m *AbstractMap) IsLoaded() bool {
	return m.Loaded
}

func (m *AbstractMap) GetName() ObjName {
	return m.Name
}

func (m *AbstractMap) GetFD() bpfsys.BPFfd {
	return m.Fd
}

func (m *AbstractMap) GetDefinition() BPFMapDef {
	return m.Definition
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
			"key type size(%d) doesn't match size of bfp key(%d)",
			keyType.Elem().Size(),
			m.Definition.KeySize,
		)
	}

	return reflect.ValueOf(key).Pointer(), nil
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

var BPFMapDefSize = int(unsafe.Sizeof(BPFMapDef{}))

type BPFMapDef struct {
	Type       bpftypes.BPFMapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      bpftypes.BPFMapFlags
}

// Equal checks if two map definitions are functionally identical
func (def BPFMapDef) Equal(other BPFMapDef) bool {
	return def.Type == other.Type &&
		def.KeySize == other.KeySize &&
		def.ValueSize == other.ValueSize &&
		def.MaxEntries == other.MaxEntries &&
		def.Flags == other.Flags
}

// Validate checks if the map definition is valid, the kernel also does these checks but if the kernel finds an error
// it doesn't return a nice error message. This give a better user experience.
func (def BPFMapDef) Validate() error {
	if kfeat, found := mapTypeToKFeature[def.Type]; found {
		if !kernelsupport.CurrentFeatures.Map.Has(kfeat) {
			return fmt.Errorf("map type '%s' not supported: %s", def.Type, bpfsys.ErrNotSupported)
		}
	}

	if err := def.validateSizes(); err != nil {
		return err
	}

	if err := def.validateFlags(); err != nil {
		return err
	}

	switch def.Type {
	case bpftypes.BPF_MAP_TYPE_STACK_TRACE:
		// TODO value_size % 8 == 0
		// TODO stack build id check https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/stackmap.c#L108
	case bpftypes.BPF_MAP_TYPE_DEVMAP, bpftypes.BPF_MAP_TYPE_DEVMAP_HASH:
		// TODO check value_size, which is dependant on host architecture
	case bpftypes.BPF_MAP_TYPE_SOCKMAP:
		// TODO check value_size, which is dependant on host architecture
	case bpftypes.BPF_MAP_TYPE_CPUMAP:
		// TODO check value_size, which is dependant on host architecture
	case bpftypes.BPF_MAP_TYPE_CGROUP_STORAGE, bpftypes.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
		bpftypes.BPF_MAP_TYPE_INODE_STORAGE, bpftypes.BPF_MAP_TYPE_TASK_STORAGE:
		// TODO check key_size
	case bpftypes.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
		// TODO check value size
	case bpftypes.BPF_MAP_TYPE_STRUCT_OPS:
		// TODO check key size
	case bpftypes.BPF_MAP_TYPE_RINGBUF:
		// TODO max_entries is a power of 2 and page aligned
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/ringbuf.c#L154
	}

	return nil
}

func (def BPFMapDef) validateFlags() error {

	requiredFlags := map[bpftypes.BPFMapType][]bpftypes.BPFMapFlags{
		bpftypes.BPF_MAP_TYPE_LPM_TRIE: {
			bpftypes.BPFMapFlagsNoPreAlloc,
		},
	}

	if rFlags, ok := requiredFlags[def.Type]; ok {
		for _, requiredFlag := range rFlags {
			if def.Flags&requiredFlag == 0 {
				return fmt.Errorf("maps of type %s must have the the %s flag set, map has the following flags set: %s",
					def.Type, requiredFlag, def.Flags)
			}
		}
	}

	permittedFlags := map[bpftypes.BPFMapType]bpftypes.BPFMapFlags{
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L369
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L17
		bpftypes.BPF_MAP_TYPE_HASH: bpftypes.BPFMapFlagsNoPreAlloc |
			bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsZeroSeed,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L631
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L17
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L51
		bpftypes.BPF_MAP_TYPE_ARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsMMapable |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsInnerMap,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L1046
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L668
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_PROG_ARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L1153
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L668
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L369
		bpftypes.BPF_MAP_TYPE_PERCPU_HASH: bpftypes.BPFMapFlagsNoPreAlloc |
			bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsZeroSeed,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L654
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L17
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/stackmap.c#L16
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/stackmap.c#L89
		bpftypes.BPF_MAP_TYPE_STACK_TRACE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsStackBuildID,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L1190
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L668
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_CGROUP_ARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L369
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L404
		bpftypes.BPF_MAP_TYPE_LRU_HASH: bpftypes.BPFMapFlagsNoCommonLRU |
			bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsZeroSeed,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L369
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/hashtab.c#L404
		bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH: bpftypes.BPFMapFlagsNoCommonLRU |
			bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsZeroSeed,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/lpm_trie.c#L537
		bpftypes.BPF_MAP_TYPE_LPM_TRIE: bpftypes.BPFMapFlagsNoPreAlloc |
			bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L1276
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L668
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L1046
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L668
		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/arraymap.c#L59
		bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		bpftypes.BPF_MAP_TYPE_DEVMAP: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		bpftypes.BPF_MAP_TYPE_SOCKMAP: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		bpftypes.BPF_MAP_TYPE_CPUMAP: bpftypes.BPFMapFlagsNUMANode,

		bpftypes.BPF_MAP_TYPE_XSKMAP: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// bpftypes.BPF_MAP_TYPE_SOCKHASH:

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/local_storage.c#L18
		bpftypes.BPF_MAP_TYPE_CGROUP_STORAGE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/reuseport_array.c#L43
		bpftypes.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsMMapable |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg |
			bpftypes.BPFMapFlagsInnerMap,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/local_storage.c#L18
		bpftypes.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/queue_stack_maps.c#L13
		bpftypes.BPF_MAP_TYPE_QUEUE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/queue_stack_maps.c#L13
		bpftypes.BPF_MAP_TYPE_STACK: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		// bpftypes.BPF_MAP_TYPE_SK_STORAGE:

		bpftypes.BPF_MAP_TYPE_DEVMAP_HASH: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly,

		// https://elixir.bootlin.com/linux/v5.11.15/source/kernel/bpf/bpf_struct_ops.c#L540
		bpftypes.BPF_MAP_TYPE_STRUCT_OPS: 0,

		bpftypes.BPF_MAP_TYPE_RINGBUF: bpftypes.BPFMapFlagsNUMANode,

		bpftypes.BPF_MAP_TYPE_INODE_STORAGE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,

		bpftypes.BPF_MAP_TYPE_TASK_STORAGE: bpftypes.BPFMapFlagsNUMANode |
			bpftypes.BPFMapFlagsReadOnly |
			bpftypes.BPFMapFlagsWriteOnly |
			bpftypes.BPFMapFlagsReadOnlyProg |
			bpftypes.BPFMapFlagsWriteOnlyProg,
	}

	if pFlags, ok := permittedFlags[def.Type]; ok {
		// For each flag that exists
		for f := bpftypes.BPFMapFlags(1); f < bpftypes.BPFMapFlagsMax; f = f << 1 {
			// If this flag is in the def and it is not permitted
			if def.Flags&f > 0 && f&pFlags == 0 {
				return fmt.Errorf(
					"maps of type %s may not have the %s flag set, "+
						"map has the following flags set: %s, "+
						"only the following flags are allowed: %s",
					def.Type, f, def.Flags, pFlags)
			}
		}

		// If both the program read-only and write-only flags are set
		if def.Flags&(bpftypes.BPFMapFlagsReadOnlyProg|bpftypes.BPFMapFlagsWriteOnlyProg) ==
			(bpftypes.BPFMapFlagsReadOnlyProg | bpftypes.BPFMapFlagsWriteOnlyProg) {
			return fmt.Errorf(
				"the %s and %s flags are mutually exclusive",
				bpftypes.BPFMapFlagsReadOnlyProg,
				bpftypes.BPFMapFlagsWriteOnlyProg,
			)
		}
	}

	return nil
}

func (def BPFMapDef) validateSizes() error {
	keySizes := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_ARRAY:               4,
		bpftypes.BPF_MAP_TYPE_PROG_ARRAY:          4,
		bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY:    4,
		bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:        4,
		bpftypes.BPF_MAP_TYPE_STACK_TRACE:         4,
		bpftypes.BPF_MAP_TYPE_CGROUP_ARRAY:        4,
		bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:       4,
		bpftypes.BPF_MAP_TYPE_DEVMAP:              4,
		bpftypes.BPF_MAP_TYPE_SOCKMAP:             4,
		bpftypes.BPF_MAP_TYPE_CPUMAP:              4,
		bpftypes.BPF_MAP_TYPE_XSKMAP:              4,
		bpftypes.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: 4,
		bpftypes.BPF_MAP_TYPE_QUEUE:               0,
		bpftypes.BPF_MAP_TYPE_STACK:               0,
		bpftypes.BPF_MAP_TYPE_DEVMAP_HASH:         4,
		bpftypes.BPF_MAP_TYPE_RINGBUF:             0,
	}

	if exactSize, ok := keySizes[def.Type]; ok && exactSize != def.KeySize {
		return fmt.Errorf("maps of type %s must always have a key size of %d bytes, "+
			"key size of this map is %d bytes", def.Type, exactSize, def.KeySize)
	}

	minKeySizes := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_HASH:            1,
		bpftypes.BPF_MAP_TYPE_PERCPU_HASH:     1,
		bpftypes.BPF_MAP_TYPE_LRU_HASH:        1,
		bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH: 1,
		bpftypes.BPF_MAP_TYPE_LPM_TRIE:        6,
	}

	if minSize, ok := minKeySizes[def.Type]; ok && def.KeySize < minSize {
		return fmt.Errorf("maps of type %s must have a key size of at least %d bytes, "+
			"key size of this map is %d bytes", def.Type, minSize, def.KeySize)
	}

	exactValueSizes := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_PROG_ARRAY:       4,
		bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY: 4,
		bpftypes.BPF_MAP_TYPE_CGROUP_ARRAY:     4,
		bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:    4,
		bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS:     4,
		bpftypes.BPF_MAP_TYPE_XSKMAP:           4,
		bpftypes.BPF_MAP_TYPE_RINGBUF:          0,
	}

	if exactSize, ok := exactValueSizes[def.Type]; ok && exactSize != def.ValueSize {
		return fmt.Errorf("maps of type %s must always have a value size of %d bytes, "+
			"value size of this map is %d bytes", def.Type, exactSize, def.ValueSize)
	}

	minValueSizes := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_HASH:                  1,
		bpftypes.BPF_MAP_TYPE_ARRAY:                 1,
		bpftypes.BPF_MAP_TYPE_PERCPU_HASH:           1,
		bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:          1,
		bpftypes.BPF_MAP_TYPE_STACK_TRACE:           8,
		bpftypes.BPF_MAP_TYPE_LRU_HASH:              1,
		bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH:       1,
		bpftypes.BPF_MAP_TYPE_LPM_TRIE:              1,
		bpftypes.BPF_MAP_TYPE_CGROUP_STORAGE:        1,
		bpftypes.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: 1,
		bpftypes.BPF_MAP_TYPE_QUEUE:                 1,
		bpftypes.BPF_MAP_TYPE_STACK:                 1,
		bpftypes.BPF_MAP_TYPE_INODE_STORAGE:         1,
		bpftypes.BPF_MAP_TYPE_TASK_STORAGE:          1,
	}

	if minSize, ok := minValueSizes[def.Type]; ok && def.ValueSize < minSize {
		return fmt.Errorf("maps of type %s must have a value size of at least %d bytes, "+
			"value size of this map is %d bytes", def.Type, minSize, def.ValueSize)
	}

	minEntries := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_HASH:                1,
		bpftypes.BPF_MAP_TYPE_ARRAY:               1,
		bpftypes.BPF_MAP_TYPE_PROG_ARRAY:          1,
		bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY:    1,
		bpftypes.BPF_MAP_TYPE_PERCPU_HASH:         1,
		bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:        1,
		bpftypes.BPF_MAP_TYPE_CGROUP_ARRAY:        1,
		bpftypes.BPF_MAP_TYPE_LRU_HASH:            1,
		bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH:     1,
		bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:       1,
		bpftypes.BPF_MAP_TYPE_DEVMAP:              1,
		bpftypes.BPF_MAP_TYPE_SOCKMAP:             1,
		bpftypes.BPF_MAP_TYPE_CPUMAP:              1,
		bpftypes.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: 1,
		bpftypes.BPF_MAP_TYPE_DEVMAP_HASH:         1,
		bpftypes.BPF_MAP_TYPE_STRUCT_OPS:          1,
	}

	if minEntries, ok := minEntries[def.Type]; ok && def.MaxEntries < minEntries {
		return fmt.Errorf("maps of type %s must have a max_entries number of at least %d, "+
			"max_entries of this map is %d", def.Type, minEntries, def.MaxEntries)
	}

	maxEntries := map[bpftypes.BPFMapType]uint32{
		bpftypes.BPF_MAP_TYPE_CGROUP_STORAGE:        0,
		bpftypes.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: 0,
		bpftypes.BPF_MAP_TYPE_STRUCT_OPS:            1,
		bpftypes.BPF_MAP_TYPE_INODE_STORAGE:         0,
		bpftypes.BPF_MAP_TYPE_TASK_STORAGE:          0,
	}

	if maxEntries, ok := maxEntries[def.Type]; ok && def.MaxEntries > maxEntries {
		return fmt.Errorf("maps of type %s must have a max_entries number of at most %d, "+
			"max_entries of this map is %d", def.Type, maxEntries, def.MaxEntries)
	}

	return nil
}

var mapTypeToKFeature = map[bpftypes.BPFMapType]kernelsupport.MapSupport{
	bpftypes.BPF_MAP_TYPE_HASH:                  kernelsupport.KFeatMapHash,
	bpftypes.BPF_MAP_TYPE_ARRAY:                 kernelsupport.KFeatMapArray,
	bpftypes.BPF_MAP_TYPE_PROG_ARRAY:            kernelsupport.KFeatMapTailCall,
	bpftypes.BPF_MAP_TYPE_PERF_EVENT_ARRAY:      kernelsupport.KFeatMapPerfEvent,
	bpftypes.BPF_MAP_TYPE_PERCPU_HASH:           kernelsupport.KFeatMapPerCPUHash,
	bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:          kernelsupport.KFeatMapPerCPUArray,
	bpftypes.BPF_MAP_TYPE_STACK_TRACE:           kernelsupport.KFeatMapStackTrace,
	bpftypes.BPF_MAP_TYPE_CGROUP_ARRAY:          kernelsupport.KFeatMapCGroupArray,
	bpftypes.BPF_MAP_TYPE_LRU_HASH:              kernelsupport.KFeatMapLRUHash,
	bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH:       kernelsupport.KFeatMapLRUPerCPUHash,
	bpftypes.BPF_MAP_TYPE_LPM_TRIE:              kernelsupport.KFeatMapLPMTrie,
	bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:         kernelsupport.KFeatMapArrayOfMaps,
	bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS:          kernelsupport.KFeatMapHashOfMaps,
	bpftypes.BPF_MAP_TYPE_DEVMAP:                kernelsupport.KFeatMapNetdevArray,
	bpftypes.BPF_MAP_TYPE_SOCKMAP:               kernelsupport.KFeatMapSocketArray,
	bpftypes.BPF_MAP_TYPE_CPUMAP:                kernelsupport.KFeatMapCPU,
	bpftypes.BPF_MAP_TYPE_XSKMAP:                kernelsupport.KFeatMapAFXDP,
	bpftypes.BPF_MAP_TYPE_SOCKHASH:              kernelsupport.KFeatMapSocketHash,
	bpftypes.BPF_MAP_TYPE_CGROUP_STORAGE:        kernelsupport.KFeatMapCGroupStorage,
	bpftypes.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:   kernelsupport.KFeatMapReuseportSocketArray,
	bpftypes.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: kernelsupport.KFeatMapPerCPUCGroupStorage,
	bpftypes.BPF_MAP_TYPE_QUEUE:                 kernelsupport.KFeatMapQueue,
	bpftypes.BPF_MAP_TYPE_STACK:                 kernelsupport.KFeatMapStack,
	bpftypes.BPF_MAP_TYPE_SK_STORAGE:            kernelsupport.KFeatMapSocketLocalStorage,
	bpftypes.BPF_MAP_TYPE_DEVMAP_HASH:           kernelsupport.KFeatMapNetdevHash,
	bpftypes.BPF_MAP_TYPE_STRUCT_OPS:            kernelsupport.KFeatMapStructOps,
	bpftypes.BPF_MAP_TYPE_RINGBUF:               kernelsupport.KFeatMapRingBuffer,
	bpftypes.BPF_MAP_TYPE_INODE_STORAGE:         kernelsupport.KFeatMapINodeStorage,
	bpftypes.BPF_MAP_TYPE_TASK_STORAGE:          kernelsupport.KFeatMapTaskStorage,
}
