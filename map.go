package gobpfld

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/internal/cstr"
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

	// Close closes the file descriptor associated with the map. The map can't be used after it is closed.
	// If this is the last file descriptor pointing to the map, the map will be unloaded from the kernel.
	// If a map is pinned to the filesystem, in use by a bpf program or referenced any other way it will stay loaded
	// until all references are closed/removed.
	Close() error
}

// MapFromFD creates a BPFMap object from a map that is already loaded into the kernel and for which we already have
// a file descriptor.
func MapFromFD(fd bpfsys.BPFfd) (BPFMap, error) {
	// Check if there already is a map in the register with this FD.
	m := mapRegister.getByFD(fd)
	if m != nil {
		return m, nil
	}

	// Otherwise get all required info from the kernel and create a userspace representation.

	mapInfo, err := getMapInfo(fd)
	if err != nil {
		return nil, err
	}

	// TODO if the type is an memory mmap-able array, we should mmap it so it can be used.

	m = bpfMapFromAbstractMap(
		AbstractMap{
			Name: ObjName{
				cname: mapInfo.Name,
				str:   cstr.BytesToString(mapInfo.Name[:]),
			},
			loaded: true,
			fd:     fd,
			Definition: BPFMapDef{
				Type:       mapInfo.Type,
				KeySize:    mapInfo.KeySize,
				ValueSize:  mapInfo.ValueSize,
				MaxEntries: mapInfo.MaxEntries,
				Flags:      bpftypes.BPFMapFlags(mapInfo.MapFlags),
			},
			definition: BPFMapDef{
				Type:       mapInfo.Type,
				KeySize:    mapInfo.KeySize,
				ValueSize:  mapInfo.ValueSize,
				MaxEntries: mapInfo.MaxEntries,
				Flags:      bpftypes.BPFMapFlags(mapInfo.MapFlags),
			},
		},
	)

	err = mapRegister.add(m)
	if err != nil {
		return nil, fmt.Errorf("map register: %w", err)
	}

	return m, nil
}

// MapFromID creates a BPFMap object from a map that is already loaded into the kernel.
func MapFromID(id uint32) (BPFMap, error) {
	// First check if we already have a version of this map in the register
	m := mapRegister.getByID(id)
	if m != nil {
		return m, nil
	}

	// If no, get a new FD from the ID and construct a map.

	fd, err := bpfsys.MapGetFDByID(&bpfsys.BPFAttrGetID{
		ID: id,
	})
	if err != nil {
		return nil, fmt.Errorf("bpf syscall error: %w", err)
	}

	return MapFromFD(fd)
}

// mapIDRegister holds a reference to all maps currently loaded into the kernel. The map is index by the object ID
// of the map which uniquely identifies it within the kernel. The purpose of this is that if the user re-gets a map
// via any mechanism(FS pinning, ID, FD, or map-in-map) that the user always gets the same instance(pointer) to the map.
// Because the user will always have the same object, we will also have only one FD which is easier for the user to
// manage.
var mapRegister = _mapRegister{
	idToMap: make(map[uint32]BPFMap),
	fdToMap: make(map[bpfsys.BPFfd]BPFMap),
}

type _mapRegister struct {
	mu      sync.Mutex
	idToMap map[uint32]BPFMap
	fdToMap map[bpfsys.BPFfd]BPFMap
}

func (r *_mapRegister) add(m BPFMap) error {
	if !m.IsLoaded() {
		return fmt.Errorf("can only add loaded maps to the register")
	}

	// Get info from kernel via the FD so we can get the ID of this map
	info, err := getMapInfo(m.GetFD())
	if err != nil {
		return fmt.Errorf("get map info: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.idToMap[info.ID] = m
	r.fdToMap[m.GetFD()] = m

	return nil
}

func (r *_mapRegister) delete(m BPFMap) error {
	if !m.IsLoaded() {
		return fmt.Errorf("can only delete loaded maps from the register")
	}

	// Get info from kernel via the FD so we can get the ID of this map
	info, err := getMapInfo(m.GetFD())
	if err != nil {
		return fmt.Errorf("get map info: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.idToMap, info.ID)
	delete(r.fdToMap, m.GetFD())

	return nil
}

func (r *_mapRegister) getByID(id uint32) BPFMap {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.idToMap[id]
}

func (r *_mapRegister) getByFD(fd bpfsys.BPFfd) BPFMap {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.fdToMap[fd]
}

func getMapInfo(fd bpfsys.BPFfd) (bpftypes.BPFMapInfo, error) {
	mapInfo := bpftypes.BPFMapInfo{}
	err := bpfsys.ObjectGetInfoByFD(&bpfsys.BPFAttrGetInfoFD{
		BPFFD:   fd,
		Info:    uintptr(unsafe.Pointer(&mapInfo)),
		InfoLen: uint32(bpftypes.BPFMapInfoSize),
	})
	if err != nil {
		return mapInfo, fmt.Errorf("bpf obj get info by fd syscall error: %w", err)
	}

	return mapInfo, nil
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

	case bpftypes.BPF_MAP_TYPE_ARRAY_OF_MAPS:
		return &ArrayOfMapsMap{
			AbstractMap: am,
		}

	case bpftypes.BPF_MAP_TYPE_HASH_OF_MAPS:
		return &HashOfMapsMap{
			AbstractMap: am,
		}

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
	case bpftypes.BPF_MAP_TYPE_STACK:
		return &StackMap{
			AbstractMap: am,
		}
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
