package gobpfld

import (
	"fmt"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

type BPFMap interface {
	GetName() ObjName
	GetFD() bpfsys.BPFfd
	IsLoaded() bool
	GetDefinition() BPFMapDef

	Load() error
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

var BPFMapDefSize = int(unsafe.Sizeof(BPFMapDef{}))

type BPFMapDef struct {
	Type       bpftypes.BPFMapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      bpftypes.BPFMapFlags
}

// Validate checks if the map definition is valid, the kernel also does these checks but if the kernel finds an error
// it doesn't return a nice error message. This give a better user experience.
func (def BPFMapDef) Validate() error {
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
