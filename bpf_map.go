package gobpfld

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
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

var _ BPFMap = (*BPFGenericMap)(nil)

// BPFGenericMap is a generic implementation of BPFMap.
// Because it uses reflection for type information it is slower than any application specific map.
// For high speed access a custom BPFMap implementation is recommended
type BPFGenericMap struct {
	Name ObjName

	Loaded bool
	Fd     bpfsys.BPFfd

	Definition BPFMapDef
}

func (m *BPFGenericMap) Load() error {
	attr := &bpfsys.BPFAttrMapCreate{
		MapName:    m.Name.GetCstr(),
		MapType:    m.Definition.Type,
		KeySize:    m.Definition.KeySize,
		ValueSize:  m.Definition.ValueSize,
		MaxEntries: m.Definition.MaxEntries,
		MapFlags:   m.Definition.Flags,
	}

	var err error
	m.Fd, err = bpfsys.MapCreate(attr)
	if err != nil {
		spew.Dump(err)
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	m.Loaded = true

	return nil
}

func (m *BPFGenericMap) IsLoaded() bool {
	return m.Loaded
}

func (m *BPFGenericMap) GetName() ObjName {
	return m.Name
}

func (m *BPFGenericMap) GetFD() bpfsys.BPFfd {
	return m.Fd
}

func (m *BPFGenericMap) GetDefinition() BPFMapDef {
	return m.Definition
}

func (m *BPFGenericMap) Get(key interface{}, value interface{}) error {
	if !m.Loaded {
		return fmt.Errorf("can't read from an unloaded map")
	}

	attr := &bpfsys.BPFAttrMapElem{
		MapFD: m.Fd,
	}

	keyType := reflect.TypeOf(key)
	if keyType.Kind() != reflect.Ptr {
		return fmt.Errorf("key argument must be a pointer")
	}

	if keyType.Elem().Size() != uintptr(m.Definition.KeySize) {
		return fmt.Errorf(
			"key type size(%d) doesn't match size of bfp key(%d)",
			keyType.Elem().Size(),
			m.Definition.KeySize,
		)
	}

	attr.Key = reflect.ValueOf(key).Pointer()

	valueType := reflect.TypeOf(value)
	if valueType.Kind() != reflect.Ptr {
		return fmt.Errorf("value argument must be a pointer")
	}

	if valueType.Elem().Size() != uintptr(m.Definition.ValueSize) {
		return fmt.Errorf(
			"value type size(%d) doesn't match size of bfp value(%d)",
			valueType.Elem().Size(),
			m.Definition.ValueSize,
		)
	}

	attr.Value_NextKey = reflect.ValueOf(value).Pointer()

	err := bpfsys.MapLookupElem(attr)
	if err != nil {
		return fmt.Errorf("bpf syscall error: %w", err)
	}

	return nil
}

var BPFMapDefSize = int(unsafe.Sizeof(BPFMapDef{}))

type BPFMapDef struct {
	Type       bpftypes.BPFMapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}
