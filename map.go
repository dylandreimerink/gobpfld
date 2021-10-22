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

	// Pin pins the map to a location in the bpf filesystem, since the file system now also holds a reference
	// to the map the original creator of the map can terminate without triggering the map to be closed as well.
	// A map can be unpinned from the bpf FS by another process thus transferring it or persisting it across
	// multiple runs of the same program.
	Pin(relativePath string) error

	// Unpin captures the file descriptor of the map at the given 'relativePath' from the kernel.
	// The definition in this map must match the definition of the pinned map, otherwise this function
	// will return an error since mismatched definitions might cause seemingly unrelated bugs in other functions.
	// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the map, thus transferring
	// ownership of the map in a scenario where the map is not shared between multiple programs.
	// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
	Unpin(relativePath string, deletePin bool) error

	// Load validates and loads the userspace map definition into the kernel.
	Load() error
	Unload() error
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

	return bpfMapFromAbstractMap(
		AbstractMap{
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
	), nil
}

// bpfMapFromAbstractMap takes in an abstract map and uses the values in the definion to construct a specific map type
// which implements BPFMap
func bpfMapFromAbstractMap(am AbstractMap) BPFMap {
	switch am.Definition.Type {
	case bpftypes.BPF_MAP_TYPE_HASH:
		return &HashMap{
			AbstractMap: am,
		}

	case bpftypes.BPF_MAP_TYPE_ARRAY:
		return &ArrayMap{
			AbstractMap: am,
		}

	case bpftypes.BPF_MAP_TYPE_PROG_ARRAY:
		return &ProgArrayMap{
			AbstractMap: am,
		}

		// TODO BPF_MAP_TYPE_PERF_EVENT_ARRAY

	case bpftypes.BPF_MAP_TYPE_PERCPU_HASH:
		return &HashMap{
			AbstractMap: am,
		}

	case bpftypes.BPF_MAP_TYPE_PERCPU_ARRAY:
		return &PerCPUArrayMap{
			AbstractMap: am,
		}

		// TODO BPF_MAP_TYPE_STACK_TRACE

	case bpftypes.BPF_MAP_TYPE_LRU_HASH,
		bpftypes.BPF_MAP_TYPE_LRU_PERCPU_HASH:
		return &HashMap{
			AbstractMap: am,
		}

	case bpftypes.BPF_MAP_TYPE_LPM_TRIE:
		return &LPMTrieMap{
			AbstractMap: am,
		}

		// TODO BPF_MAP_TYPE_ARRAY_OF_MAPS
		// TODO BPF_MAP_TYPE_HASH_OF_MAPS
		// TODO BPF_MAP_TYPE_DEVMAP
		// TODO BPF_MAP_TYPE_SOCKMAP
		// TODO BPF_MAP_TYPE_CPUMAP

	case bpftypes.BPF_MAP_TYPE_XSKMAP:
		return &XSKMap{
			AbstractMap: am,
		}

		// TODO BPF_MAP_TYPE_SOCKHASH
		// TODO BPF_MAP_TYPE_CGROUP_STORAGE
		// TODO BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
		// TODO BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
		// TODO BPF_MAP_TYPE_QUEUE
		// TODO BPF_MAP_TYPE_STACK
		// TODO BPF_MAP_TYPE_SK_STORAGE
		// TODO BPF_MAP_TYPE_DEVMAP_HASH
		// TODO BPF_MAP_TYPE_STRUCT_OPS
		// TODO BPF_MAP_TYPE_RINGBUF
		// TODO BPF_MAP_TYPE_INODE_STORAGE
		// TODO BPF_MAP_TYPE_TASK_STORAGE

	default:
		return &HashMap{
			AbstractMap: am,
		}
	}
}

const maxUint32 = int(^uint32(0))
