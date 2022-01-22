package gobpfld

import (
	"fmt"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

var _ BPFMap = (*dataMap)(nil)

// dataMap is a special map type which is used to load relocated data from .data, .rodata and .bss sections.
// It is actually an array map, but its contents are set just after loading, an this map has no exposed functions
// to be used by users of the library.
type dataMap struct {
	AbstractMap

	readOnly bool
}

func (m *dataMap) Load() error {
	err := m.load(func(attr *bpfsys.BPFAttrMapCreate) {
		attr.MapType = bpftypes.BPF_MAP_TYPE_ARRAY

		if m.readOnly {
			if kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapBPFRW) {
				attr.MapFlags |= bpftypes.BPFMapFlagsReadOnlyProg
			}
		}
	})
	if err != nil {
		return fmt.Errorf("error while loading map: %w", err)
	}

	err = mapRegister.add(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	// TODO move to abstract map load
	if m.InitialData[0] != nil {
		k := uint32(0)
		attr := bpfsys.BPFAttrMapElem{
			MapFD: m.fd,
			Flags: bpfsys.BPFMapElemAny,
		}

		attr.Key, err = m.toKeyPtr(&k)
		if err != nil {
			return fmt.Errorf("unable to make ptr of uint32(0): %w", err)
		}

		if len(m.InitialData[0].([]byte)) != int(m.definition.ValueSize) {
			return fmt.Errorf(
				"initial data(%d) not of same size as map definition(%d)",
				len(m.InitialData),
				int(m.definition.ValueSize),
			)
		}

		value, ok := m.InitialData[0].([]byte)
		if !ok {
			panic("initial data value of a dataMap isn't []byte")
		}
		attr.Value_NextKey = uintptr(unsafe.Pointer(&value[0]))

		err = bpfsys.MapUpdateElem(&attr)
		if err != nil {
			return fmt.Errorf("bpf syscall error: %w", err)
		}
	}

	// Freeze the map if it is supposed to be read only
	if m.readOnly && kernelsupport.CurrentFeatures.API.Has(kernelsupport.KFeatAPIMapFreeze) {
		err = bpfsys.MapFreeze(&bpfsys.BPFAttrMapElem{
			MapFD: m.fd,
		})
		if err != nil {
			return fmt.Errorf("freeze map: %w", err)
		}
	}

	return nil
}

// Close closes the file descriptor associate with the map, this will cause the map to unload from the kernel
// if it is not still in use by a eBPF program, bpf FS, or a userspace program still holding a fd to the map.
func (m *dataMap) Close() error {
	err := mapRegister.delete(m)
	if err != nil {
		return fmt.Errorf("map register: %w", err)
	}

	return m.close()
}
