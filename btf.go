package gobpfld

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/internal/cstr"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

// TODO add field to store kernel structure ID's (for map BTFVMLinuxValueTypeID)
// TODO Add global registry for BTF objects to translate IDs to FDs
// TODO Add fuzzing, we should never get panics only errors, critical for stability of library users. (go 1.18)
// TODO (bonus) make code generators for BTF so we can generate C and Go code like bpftool does
// TODO (bonus) test against VMLinux (/sys/kernel/btf/vmlinux)
// TODO (bonus) implement libbpf compatible CO:RE(Compile Once Run Everywhere).
//   This works by looking at the BTF of the compiled program to see what it wants to access and rewriting
//   the program using the VMLinux on the machine at runtime. This would enable users to compile architecture
//   specific kprobe or uprobe code and run it everywhere.

// BTF Type and String info
type BTF struct {
	// Parsed type information, the index of the types is equal to their ID's
	Types []BTFType

	// Parsed Lines information with ELF section relative instruction offsets
	Lines []BTFLine
	// Parsed function information with ELF section relative instruction offsets
	Funcs []BTFFunc

	// A mapping of BTF types indexed on name, used to find the currect types for BPF Maps
	typesByName map[string]BTFType

	// The parsed BTF header
	btfHdr *btfHeader
	// Contains the full, raw BTF header, string and type bytes.
	// Used to load into the kernel.
	rawType []byte

	StringsTbl StringTbl

	// The parsed BTF EXT header
	btfExtHdr *btfExtHeader

	// Indicates if the BTF is already loaded into the kernel
	loaded bool
	// The file descriptor of the BTF assigned by the kernel
	fd bpfsys.BPFfd
}

func NewBTF() *BTF {
	return &BTF{
		typesByName: make(map[string]BTFType),
	}
}

func (btf *BTF) Fd() (bpfsys.BPFfd, error) {
	if !btf.loaded {
		return 0, fmt.Errorf("btf is not loaded")
	}

	return btf.fd, nil
}

type BTFLoadOpts struct {
	LogLevel bpftypes.BPFLogLevel
	LogSize  int
}

func (btf *BTF) Load(opts BTFLoadOpts) (string, error) {
	if btf.loaded {
		return "", fmt.Errorf("btf is already loaded")
	}

	if btf.rawType == nil {
		return "", fmt.Errorf("btf has no raw type info")
	}

	// Set a default log size if none is specified
	if opts.LogSize == 0 {
		opts.LogSize = defaultBPFVerifierLogSize
	}

	serialized, err := btf.SerializeBTF()
	if err != nil {
		return "", fmt.Errorf("btf serialization: %w", err)
	}

	verifierLogBytes := make([]byte, opts.LogSize)

	attr := bpfsys.BPFAttrBTFLoad{
		BTF:         uintptr(unsafe.Pointer(&serialized[0])),
		BTFSize:     uint32(len(serialized)),
		BTFLogBuf:   uintptr(unsafe.Pointer(&verifierLogBytes[0])),
		BTFLogSize:  uint32(opts.LogSize),
		BTFLogLevel: opts.LogLevel,
	}

	fd, err := bpfsys.BTFLoad(&attr)
	if err != nil {
		return cstr.BytesToString(verifierLogBytes), err
	}

	btf.fd = fd
	btf.loaded = true

	return cstr.BytesToString(verifierLogBytes), nil
}

// ErrMissingBTFData is returned when a datastructure indicates that there should be additional bytes but
//  the given bytes slice doesn't contain any.
var ErrMissingBTFData = errors.New("missing indicated bytes in slice")

// ParseBTF parses BTF type and string data.
func (btf *BTF) ParseBTF(btfBytes []byte) error {
	btf.rawType = btfBytes
	headerOffset := uint32(0)

	var err error
	btf.btfHdr, headerOffset, err = parseBTFHeader(btfBytes)
	if err != nil {
		return fmt.Errorf("parse header: %w", err)
	}

	btfLen := len(btfBytes)
	if btfLen < int(headerOffset+btf.btfHdr.StringOffset+btf.btfHdr.StringLength) {
		return fmt.Errorf("byte sequence shorten than indicated string offset + length")
	}

	stringsStart := headerOffset + btf.btfHdr.StringOffset
	stringsEnd := headerOffset + btf.btfHdr.StringOffset + btf.btfHdr.StringLength
	btf.StringsTbl = StringTblFromBlob(btfBytes[stringsStart:stringsEnd])

	if btfLen < int(headerOffset+btf.btfHdr.TypeOffset+btf.btfHdr.TypeLength) {
		return fmt.Errorf("byte sequence shorten than indicated type offset + length")
	}

	typesStart := headerOffset + btf.btfHdr.TypeOffset
	typesEnd := headerOffset + btf.btfHdr.TypeOffset + btf.btfHdr.TypeLength
	btfTypes := btfBytes[typesStart:typesEnd]

	var readError error
	off := 0
	read32 := func() uint32 {
		defer func() {
			off = off + 4
		}()

		// return a 0, instread of panicing
		if off+4 > len(btfTypes) {
			readError = ErrMissingBTFData
			return 0
		}

		v := btf.btfHdr.byteOrder.Uint32(btfTypes[off : off+4])
		return v
	}

	// Type ID 0 is reserved for void, this initial item will make it so that the index in this slice
	// is equal to the Type IDs used by other types.
	btf.Types = append(btf.Types, &BTFVoidType{})

	for off < len(btfTypes) {
		ct := (btfType{
			NameOffset: read32(),
			Info:       read32(),
			SizeType:   read32(),
		}).ToCommonType(&btf.StringsTbl)

		// The current amount of elements is equal to the index of the next element.
		ct.TypeID = len(btf.Types)

		var btfType BTFType
		switch ct.Kind {
		case BTF_KIND_INT:
			ct.Size = ct.sizeType
			typeData := read32()
			btfType = &BTFIntType{
				commonType: ct,
				Encoding:   BTFIntEncoding((typeData & 0x0f000000) >> 24),
				Offset:     uint8((typeData & 0x00ff0000) >> 16),
				Bits:       uint8(typeData & 0x000000ff),
			}

		case BTF_KIND_PTR:
			btfType = &BTFPtrType{
				commonType: ct,
			}

		case BTF_KIND_ARRAY:
			arr := &BTFArrayType{
				commonType: ct,
			}
			arr.typeID = read32()
			arr.indexTypeID = read32()
			arr.NumElements = read32()

			btfType = arr

		case BTF_KIND_STRUCT, BTF_KIND_UNION:
			ct.Size = ct.sizeType
			members := make([]BTFMember, ct.VLen)
			for i := 0; i < int(ct.VLen); i++ {
				members[i].Name = btf.StringsTbl.GetStringAtOffset(int(read32()))
				members[i].typeID = read32()

				// https://elixir.bootlin.com/linux/v5.15.3/source/include/uapi/linux/btf.h#L132
				offset := read32()
				if ct.KindFlag == 1 {
					// If the kind_flag is set, the btf_member.offset contains both member bitfield size and bit offset.
					members[i].BitfieldSize = offset >> 24
					members[i].BitOffset = offset & 0xffffff
				} else {
					// If the type info kind_flag is not set, the offset contains only bit offset of the member.
					members[i].BitOffset = offset
				}
			}

			if ct.Kind == BTF_KIND_STRUCT {
				btfType = &BTFStructType{
					commonType: ct,
					Members:    members,
				}
				break
			}

			btfType = &BTFUnionType{
				commonType: ct,
				Members:    members,
			}
		case BTF_KIND_ENUM:
			ct.Size = ct.sizeType
			options := make([]BTFEnumOption, ct.VLen)
			for i := 0; i < int(ct.VLen); i++ {
				options[i].Name = btf.StringsTbl.GetStringAtOffset(int(read32()))
				options[i].Value = int32(read32())
			}

			btfType = &BTFEnumType{
				commonType: ct,
				Options:    options,
			}

		case BTF_KIND_FWD:
			btfType = &BTFForwardType{
				commonType: ct,
			}

		case BTF_KIND_TYPEDEF:
			btfType = &BTFTypeDefType{
				commonType: ct,
			}

		case BTF_KIND_VOLATILE:
			btfType = &BTFVolatileType{
				commonType: ct,
			}

		case BTF_KIND_CONST:
			btfType = &BTFConstType{
				commonType: ct,
			}

		case BTF_KIND_RESTRICT:
			btfType = &BTFRestrictType{
				commonType: ct,
			}

		case BTF_KIND_FUNC:
			btfType = &BTFFuncType{
				commonType: ct,
			}

		case BTF_KIND_FUNC_PROTO:
			params := make([]BTFFuncProtoParam, ct.VLen)
			for i := 0; i < int(ct.VLen); i++ {
				params[i].Name = btf.StringsTbl.GetStringAtOffset(int(read32()))
				params[i].typeID = read32()
			}

			btfType = &BTFFuncProtoType{
				commonType: ct,
				Params:     params,
			}

		case BTF_KIND_VAR:
			btfType = &BTFVarType{
				commonType: ct,
				Linkage:    read32(),
			}

		case BTF_KIND_DATASEC:
			// The offset of the SizeType uint32 of common type
			ctSizeTypeOff := off - 4

			variables := make([]BTFDataSecVariable, ct.VLen)
			for i := 0; i < int(ct.VLen); i++ {
				variables[i].typeID = read32()
				variables[i].offsetOffset = int(typesStart) + off
				variables[i].Offset = read32()
				variables[i].Size = read32()
			}

			dataSec := &BTFDataSecType{
				commonType: ct,
				Variables:  variables,
				sizeOffset: int(typesStart) + ctSizeTypeOff,
			}
			btfType = dataSec

		case BTF_KIND_FLOAT:
			ct.Size = ct.sizeType
			btfType = &BTFFloatType{
				commonType: ct,
			}

		case BTF_KIND_DECL_TAG:
			btfType = &BTFDeclTagType{
				commonType:   ct,
				ComponentIdx: read32(),
			}

		default:
			return fmt.Errorf("unknown BTF kind: %d", ct.Kind)
		}

		btf.Types = append(btf.Types, btfType)

		if ct.Name != "" {
			btf.typesByName[ct.Name] = btfType
		}
	}
	if readError != nil {
		return readError
	}

	// Range over all types and resolve type references
	for _, btfType := range btf.Types {
		switch t := btfType.(type) {
		case *BTFPtrType:
			t.Type = btf.Types[t.sizeType]

		case *BTFArrayType:
			t.Type = btf.Types[t.typeID]
			t.IndexType = btf.Types[t.indexTypeID]

		case *BTFStructType:
			for i, member := range t.Members {
				t.Members[i].Type = btf.Types[member.typeID]
			}

		case *BTFUnionType:
			for i, member := range t.Members {
				t.Members[i].Type = btf.Types[member.typeID]
			}

		case *BTFTypeDefType:
			t.Type = btf.Types[t.sizeType]

		case *BTFVolatileType:
			t.Type = btf.Types[t.sizeType]

		case *BTFConstType:
			t.Type = btf.Types[t.sizeType]

		case *BTFRestrictType:
			t.Type = btf.Types[t.sizeType]

		case *BTFFuncType:
			t.Type = btf.Types[t.sizeType]

		case *BTFFuncProtoType:
			t.Type = btf.Types[t.sizeType]
			for i, param := range t.Params {
				t.Params[i].Type = btf.Types[param.typeID]
			}

		case *BTFVarType:
			t.Type = btf.Types[t.sizeType]

		case *BTFDataSecType:
			for i, variable := range t.Variables {
				t.Variables[i].Type = btf.Types[variable.typeID]
			}

		case *BTFDeclTagType:
			t.Type = btf.Types[t.sizeType]
		}
	}

	// Loop over all types again, this time to verify them
	// for _, btfType := range btf.Types {
	// TODO implement verification for all types.
	// TODO call verification
	// }

	return nil
}

// ParseBTFExt parses
func (btf *BTF) ParseBTFExt(btfBytes []byte) error {
	var err error
	headerOffset := uint32(0)

	btf.btfExtHdr, headerOffset, err = parseBTFExtHeader(btfBytes)
	if err != nil {
		return fmt.Errorf("parse header: %w", err)
	}

	funcsStart := headerOffset + btf.btfExtHdr.FuncOffset
	funcsEnd := headerOffset + btf.btfExtHdr.FuncOffset + btf.btfExtHdr.FuncLength
	funcs := btfBytes[funcsStart:funcsEnd]

	var readError error
	off := 0
	read32 := func() uint32 {
		defer func() {
			off = off + 4
		}()

		// return a 0, instread of panicing
		if off+4 > len(funcs) {
			readError = ErrMissingBTFData
			return 0
		}

		v := btf.btfExtHdr.byteOrder.Uint32(funcs[off : off+4])
		return v
	}

	funcRecordSize := read32()
	for off < len(funcs) {
		sectionOffset := read32()
		sectionName := btf.StringsTbl.GetStringAtOffset(int(sectionOffset))
		numInfo := read32()
		for i := 0; i < int(numInfo); i++ {
			if funcRecordSize < 8 {
				panic("func record smaller than min expected size")
			}

			f := BTFFunc{
				Section:       sectionName,
				SectionOffset: sectionOffset,
			}
			f.InstructionOffset = btf.btfExtHdr.byteOrder.Uint32(funcs[off : off+4])
			f.TypeID = btf.btfExtHdr.byteOrder.Uint32(funcs[off+4 : off+8])
			f.Type = btf.Types[f.TypeID]
			btf.Funcs = append(btf.Funcs, f)

			// Increment by funcRecordSize, since newer version of BTF might start using larger records.
			// This makes the code forward compatible
			off += int(funcRecordSize)
		}
	}
	if readError != nil {
		return err
	}

	linesStart := headerOffset + btf.btfExtHdr.LineOffset
	linesEnd := headerOffset + btf.btfExtHdr.LineOffset + btf.btfExtHdr.LineLength
	lines := btfBytes[linesStart:linesEnd]

	off = 0
	read32 = func() uint32 {
		defer func() {
			off = off + 4
		}()

		// return a 0, instread of panicing
		if off+4 > len(lines) {
			readError = ErrMissingBTFData
			return 0
		}

		v := btf.btfExtHdr.byteOrder.Uint32(lines[off : off+4])
		return v
	}

	lineRecordSize := read32()
	for off < len(lines) {
		sectionOffset := read32()
		sectionName := btf.StringsTbl.GetStringAtOffset(int(sectionOffset))
		numInfo := read32()
		for i := 0; i < int(numInfo); i++ {
			if lineRecordSize < 16 {
				panic("line record smaller than min expected size")
			}

			l := BTFLine{
				Section:       sectionName,
				SectionOffset: sectionOffset,
			}
			l.InstructionOffset = btf.btfExtHdr.byteOrder.Uint32(lines[off : off+4])
			l.FileNameOffset = btf.btfExtHdr.byteOrder.Uint32(lines[off+4 : off+8])
			l.FileName = btf.StringsTbl.GetStringAtOffset(int(l.FileNameOffset))
			l.LineOffset = btf.btfExtHdr.byteOrder.Uint32(lines[off+8 : off+12])
			l.Line = btf.StringsTbl.GetStringAtOffset(int(l.LineOffset))
			col := btf.btfExtHdr.byteOrder.Uint32(lines[off+12 : off+16])
			l.LineNumber = col >> 10
			l.ColumnNumber = col & 0x3FF
			btf.Lines = append(btf.Lines, l)

			// Increment by lineRecordSize, since newer version of BTF might start using larger records.
			// This makes the code forward compatible
			off += int(lineRecordSize)
		}
	}
	if readError != nil {
		return err
	}

	return nil
}

// SerializeBTF takes the contents BTF.Types and serializes it into a byte slice which can be loaded into the kernel
func (btf *BTF) SerializeBTF() ([]byte, error) {
	var buf bytes.Buffer

	const hdrLen = 6 * 4

	// Empty header, patched later
	buf.Write(make([]byte, hdrLen))

	btf.StringsTbl.Serialize()

	for _, t := range btf.Types[1:] {
		b, err := t.Serialize(&btf.StringsTbl, btf.btfHdr.byteOrder)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}

	typeOff := uint32(0)
	typeLen := uint32(buf.Len() - hdrLen)
	strOff := typeLen
	strLen := uint32(len(btf.StringsTbl.btfStringBlob))

	buf.Write(btf.StringsTbl.btfStringBlob)

	bytes := buf.Bytes()

	btf.btfHdr.byteOrder.PutUint16(bytes[0:2], btfMagic)
	// TODO hard code version/flags or get them from the exported fields in BTF
	bytes[2] = btf.btfHdr.Version
	bytes[3] = btf.btfHdr.Flags
	btf.btfHdr.byteOrder.PutUint32(bytes[4:8], hdrLen)

	btf.btfHdr.byteOrder.PutUint32(bytes[8:12], typeOff)
	btf.btfHdr.byteOrder.PutUint32(bytes[12:16], typeLen)
	btf.btfHdr.byteOrder.PutUint32(bytes[16:20], strOff)
	btf.btfHdr.byteOrder.PutUint32(bytes[20:24], strLen)

	return bytes, nil
}

type StringTbl struct {
	Strings       []string
	offsets       map[string]int
	btfStringBlob []byte
}

func StringTblFromBlob(blob []byte) StringTbl {
	tbl := StringTbl{
		offsets:       make(map[string]int),
		btfStringBlob: blob,
	}

	off := 0
	for _, s := range bytes.Split(blob, []byte{0}) {
		name := string(s)
		tbl.Strings = append(tbl.Strings, name)
		tbl.offsets[name] = off
		off += len(s) + 1
	}
	// Dirty fix, since we use split, the last element will register as ""
	// This will reset the map entry so an empty string will always give offset 0
	tbl.offsets[""] = 0
	tbl.Strings = tbl.Strings[:len(tbl.Strings)-1]

	return tbl
}

func (st *StringTbl) Serialize() {
	st.offsets = make(map[string]int, len(st.Strings))
	var buf bytes.Buffer
	for _, s := range st.Strings {
		st.offsets[s] = buf.Len()
		buf.WriteString(s)
		buf.WriteByte(0)
	}
	st.btfStringBlob = buf.Bytes()
}

func (st *StringTbl) GetStringAtOffset(offset int) string {
	// TODO implement stricter parsing and throw errors instead of returning empty strings.
	// NOTE current code relies on the fact that offset == 0 will return a "" which is still valid.
	//   only throw errors on offsets outside of the `strings` bounds
	var name string
	if offset < len(st.btfStringBlob) {
		idx := bytes.IndexByte(st.btfStringBlob[offset:], 0x00)
		if idx == -1 {
			name = string(st.btfStringBlob[offset:])
		} else {
			name = string(st.btfStringBlob[offset : offset+idx])
		}
	}
	return name
}

func (st *StringTbl) StrToOffset(str string) int {
	return st.offsets[str]
}

// BTFFunc the go version of bpf_func_info. Which is used to link a instruction offset to a function type.
// https://elixir.bootlin.com/linux/v5.15.3/source/include/uapi/linux/bpf.h#L6165
type BTFFunc struct {
	// The ELF section in which the function is defined
	Section string
	// Offset in the strings table to the name of the section
	SectionOffset uint32
	// Offset from the start of the ELF section to the function
	InstructionOffset uint32
	// The resolved Type of the Function
	Type BTFType
	// The TypeID, used to resolve Type
	TypeID uint32
}

func (bf BTFFunc) ToKernel() BTFKernelFunc {
	return BTFKernelFunc{
		InstructionOffset: bf.InstructionOffset,
		TypeID:            bf.TypeID,
	}
}

// BTFKernelFuncSize size of BTFKernelFunc in bytes
var BTFKernelFuncSize = int(unsafe.Sizeof(BTFKernelFunc{}))

// BTFKernelFunc is the version of the BTFFunc struct the way the kernel want to see it.
type BTFKernelFunc struct {
	InstructionOffset uint32
	TypeID            uint32
}

// BTFLine the go version of bpf_line_info. Which maps an instruction to a source code.
// https://elixir.bootlin.com/linux/v5.15.3/source/include/uapi/linux/bpf.h#L6173
type BTFLine struct {
	// The ELF section in which the line is defined
	Section string
	// The offset into the strings table for the section name
	SectionOffset uint32
	// Offset from the start of the ELF section to the function
	InstructionOffset uint32
	// The name and path of the source file
	FileName string
	// The offset into the strings table for the file name
	FileNameOffset uint32
	// The full line of source code
	Line string
	// The offset into the strings table for the line.
	LineOffset uint32
	// The line number within the file
	LineNumber uint32
	// The column number within Line of the instruction
	ColumnNumber uint32
}

func (bl BTFLine) ToKernel() BTFKernelLine {
	return BTFKernelLine{
		InstructionOffset: bl.InstructionOffset,
		FileNameOffset:    bl.FileNameOffset,
		LineOffset:        bl.LineOffset,
		LineCol:           (bl.LineNumber << 10) & bl.ColumnNumber,
	}
}

// BTFKernelLineSize size of BTFKernelLine in bytes
var BTFKernelLineSize = int(unsafe.Sizeof(BTFKernelLine{}))

// BTFKernelLine is the version of the BTFLine struct the way the kernel want to see it.
type BTFKernelLine struct {
	InstructionOffset uint32
	FileNameOffset    uint32
	LineOffset        uint32
	LineCol           uint32
}

// BTFMap is a struct which describes a BPF map
type BTFMap struct {
	Key   BTFType
	Value BTFType
}

// BTFType is a BTF type, each Kind has its own corresponding BTFType.
type BTFType interface {
	// Returns the TypeID of the type, which is determined by the position of the type within the encoded
	// BTF bytes sequence.
	GetID() int
	GetKind() BTFKind
	GetName() string
	Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error)
}

// BTFIntType is the type of KIND_INT, it represents a integer type.
type BTFIntType struct {
	commonType
	// Extra information, mainly useful for pretty printing
	Encoding BTFIntEncoding
	// specifies the starting bit offset to calculate values for this int
	Offset uint8
	// The number of actual bits held by this int type
	Bits uint8
}

func (t *BTFIntType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	commonBytes := (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_INT,
		VLen:     0,
		sizeType: t.Size,
	}.ToBTFType(strTbl).ToBytes(order))

	// TODO validate t.Encoding, t.Offset, t.Bits

	typeBytes := uint32sToBytes(order, uint32(t.Encoding)<<24|uint32(t.Offset)<<16|uint32(t.Bits))

	return append(commonBytes, typeBytes...), nil
}

// BTFIntEncoding is used to indicate what the integer encodes, used to determine how to pretty print an integer.
type BTFIntEncoding uint8

const (
	// INT_SIGNED the int should be printed at a signed integer
	INT_SIGNED BTFIntEncoding = 1 << iota
	// INT_CHAR the int should be printed as hex encoded
	INT_CHAR
	// INT_BOOL the int should be printed as a boolean
	INT_BOOL
)

var btfIntEncToStr = map[BTFIntEncoding]string{
	0:          "(none)",
	INT_SIGNED: "Signed",
	INT_CHAR:   "Char",
	INT_BOOL:   "Bool",
}

func (ie BTFIntEncoding) String() string {
	return fmt.Sprintf("%s (%d)", btfIntEncToStr[ie], ie)
}

// BTFPtrType is the type for KIND_PTR, which represents a pointer type which points to some other type.
type BTFPtrType struct {
	commonType
}

func (t *BTFPtrType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     "",
		KindFlag: 0,
		Kind:     BTF_KIND_PTR,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()),
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

// BTFArrayType is the type for KIND_ARR, which represents a array
type BTFArrayType struct {
	commonType
	// The type of the array values
	Type   BTFType
	typeID uint32
	// The type of the array index
	IndexType   BTFType
	indexTypeID uint32
	// The number of elements in the array
	NumElements uint32
}

func (t *BTFArrayType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	commonBytes := (commonType{
		Name:     "",
		KindFlag: 0,
		Kind:     BTF_KIND_ARRAY,
		VLen:     0,
		sizeType: 0,
	}.ToBTFType(strTbl).ToBytes(order))

	// TODO Perform lookup of t.Type and t.IndexType, since structs created without parting ELF can't set the
	//      non-exported values.

	return append(commonBytes, uint32sToBytes(order, t.typeID, t.indexTypeID, t.NumElements)...), nil
}

// BTFStructType is the type for KIND_STRUCT, which represents a structure.
type BTFStructType struct {
	commonType
	// The individual members / fields of the struct.
	Members []BTFMember
}

func (t *BTFStructType) Verify() error {
	for i, member := range t.Members {
		// Recursively follow type definitions to find the actual int type, or not
		// TODO move to separate functionality so it can be reused for union as well
		asInt := func() (*BTFIntType, bool) {
			curType := member.Type
			for {
				switch ct := curType.(type) {
				case *BTFIntType:
					return ct, true
				case *BTFTypeDefType:
					curType = ct.Type
					continue
				default:
					return nil, false
				}
			}
		}
		// Recursively follow type definitions to find the actual enum type, or not
		// TODO move to separate functionality so it can be reused for union as well
		asEnum := func() (*BTFEnumType, bool) {
			curType := member.Type
			for {
				switch ct := curType.(type) {
				case *BTFEnumType:
					return ct, true
				case *BTFTypeDefType:
					curType = ct.Type
					continue
				default:
					return nil, false
				}
			}
		}
		if t.KindFlag == 1 {
			// If the kind_flag is set,

			// In this case, if the base type is an int type, it must be a regular int type:
			mt, ok := asInt()
			if !ok {
				// TODO make nice error message, instead of panicing
				panic("invalid member type")
			}

			// BTF_INT_OFFSET() must be 0.
			if mt.Offset != 0 {
				// TODO make nice error message, instead of panicing
				panic("invalid int offset in struct member")
			}

			// BTF_INT_BITS() must be equal to {1,2,4,8,16} * 8
			switch mt.Bits {
			case 1 * 8, 2 * 8, 4 * 8, 8 * 8, 16 * 8:
			default:
				// TODO make nice error message, instead of panicing
				panic("invalid bits in int struct member")
			}

		} else {
			// If the type info kind_flag is not set,

			// the base type of the bitfield can only be int or enum type. If the bitfield size is 32,
			// the base type can be either int or enum type.
			if member.BitfieldSize == 32 {
				_, ok := asInt()
				if !ok {
					_, ok = asEnum()
					if !ok {
						// TODO make nice error message, instead of panicing
						panic("invalid struct member type, must be int or enum with 32 bitfield")
					}
				}
			} else {
				// If the bitfield size is not 32,
				// the base type must be int, and int type BTF_INT_BITS() encodes the bitfield size.

				// Recursively figure out if actual type is an int.
				mt, ok := asInt()
				if !ok {
					// TODO Move these checks to a 3rd iteration, since to verify this we need to be able to
					// follow type declarations. Currently it fails the
					panic("invalid struct member type, must be int for non-32 bitfield")
				}

				t.Members[i].BitfieldSize = uint32(mt.Bits)
			}
		}
	}

	return nil
}

func (t *BTFStructType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer

	const sizeOfMember = 4
	buf.Write((commonType{
		Name:     t.Name,
		KindFlag: t.KindFlag,
		Kind:     BTF_KIND_STRUCT,
		VLen:     uint16(len(t.Members)),
		sizeType: t.sizeType,
	}.ToBTFType(strTbl).ToBytes(order)))

	for _, member := range t.Members {
		var offset uint32
		if t.KindFlag == 1 {
			offset = member.BitfieldSize<<24 | (member.BitOffset & 0xffffff)
		} else {
			offset = member.BitOffset
		}

		buf.Write(uint32sToBytes(
			order,
			uint32(strTbl.StrToOffset(member.Name)),
			member.typeID, // TODO resolve from member.Type instead of relying on internal type
			offset,
		))
	}

	return buf.Bytes(), nil
}

// BTFUnionType is the type for KIND_UNION, which represents a union, where all members occupy the same memory.
type BTFUnionType struct {
	commonType
	// The individual members / fields of the union.
	Members []BTFMember
}

func (t *BTFUnionType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer

	const sizeOfMember = 4
	buf.Write((commonType{
		Name:     t.Name,
		KindFlag: t.KindFlag,
		Kind:     BTF_KIND_UNION,
		VLen:     uint16(len(t.Members)),
		sizeType: t.sizeType,
	}.ToBTFType(strTbl).ToBytes(order)))

	for _, member := range t.Members {
		var offset uint32
		if t.KindFlag == 1 {
			offset = member.BitfieldSize<<24 | (member.BitOffset & 0xffffff)
		} else {
			offset = member.BitOffset
		}

		buf.Write(uint32sToBytes(
			order,
			uint32(strTbl.StrToOffset(member.Name)),
			member.typeID, // TODO resolve from member.Type instead of relying on internal type
			offset,
		))
	}

	return buf.Bytes(), nil
}

// BTFMember is a member of a struct or union.
type BTFMember struct {
	// Name of the member/field
	Name string
	// Type of the member/field
	Type         BTFType
	typeID       uint32
	BitfieldSize uint32
	BitOffset    uint32
}

type BTFEnumType struct {
	commonType
	Options []BTFEnumOption
}

func (t *BTFEnumType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write((commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_ENUM,
		VLen:     uint16(len(t.Options)),
		sizeType: 4,
	}.ToBTFType(strTbl).ToBytes(order)))

	for _, option := range t.Options {
		buf.Write(uint32sToBytes(
			order,
			uint32(strTbl.StrToOffset(option.Name)),
			uint32(option.Value),
		))
	}

	return buf.Bytes(), nil
}

type BTFEnumOption struct {
	Name  string
	Value int32
}

type BTFForwardType struct {
	commonType
}

func (t *BTFForwardType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     t.Name,
		KindFlag: t.KindFlag,
		Kind:     BTF_KIND_FWD,
		VLen:     0,
		sizeType: 0,
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

type BTFTypeDefType struct {
	commonType
}

func (t *BTFTypeDefType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_TYPEDEF,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()), // TODO resolve ID based on index in BTF.Types
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

type BTFVolatileType struct {
	commonType
}

func (t *BTFVolatileType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     "",
		KindFlag: 0,
		Kind:     BTF_KIND_VOLATILE,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()), // TODO resolve ID based on index in BTF.Types
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

type BTFConstType struct {
	commonType
}

func (t *BTFConstType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     "",
		KindFlag: 0,
		Kind:     BTF_KIND_CONST,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()), // TODO resolve ID based on index in BTF.Types
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

type BTFRestrictType struct {
	commonType
}

func (t *BTFRestrictType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     "",
		KindFlag: 0,
		Kind:     BTF_KIND_RESTRICT,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()), // TODO resolve ID based on index in BTF.Types
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

// A BTFFuncType defines not a type, but a subprogram (function) whose signature is defined by type.
// The subprogram is thus an instance of that type.
// The KIND_FUNC may in turn be referenced by a func_info in the 4.2 .BTF.ext section (ELF) or in the arguments
// to 3.3 BPF_PROG_LOAD (ABI).
type BTFFuncType struct {
	commonType
}

func (t *BTFFuncType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	vlen := uint16(0)
	if kernelsupport.CurrentFeatures.Misc.Has(kernelsupport.KFeatBTFFuncScope) {
		vlen = t.VLen
	}

	return (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_FUNC,
		VLen:     vlen,
		sizeType: uint32(t.Type.GetID()), // TODO resolve ID based on index in BTF.Types
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

type BTFFuncProtoType struct {
	commonType
	Params []BTFFuncProtoParam
}

func (t *BTFFuncProtoType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer

	buf.Write((commonType{
		Name:     t.Name,
		KindFlag: t.KindFlag,
		Kind:     BTF_KIND_FUNC_PROTO,
		VLen:     uint16(len(t.Params)),
		sizeType: uint32(t.Type.GetID()),
	}.ToBTFType(strTbl).ToBytes(order)))

	for _, param := range t.Params {
		buf.Write(uint32sToBytes(
			order,
			uint32(strTbl.StrToOffset(param.Name)),
		))

		if param.Type == nil {
			buf.Write(uint32sToBytes(
				order,
				0,
			))
		} else {
			buf.Write(uint32sToBytes(
				order,
				uint32(param.Type.GetID()),
			))
		}
	}

	return buf.Bytes(), nil
}

type BTFFuncProtoParam struct {
	Name   string
	Type   BTFType
	typeID uint32
}

type BTFVarType struct {
	commonType
	Linkage uint32
}

func (t *BTFVarType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	commonBytes := (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_VAR,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()),
	}.ToBTFType(strTbl).ToBytes(order))

	return append(commonBytes, uint32sToBytes(order, t.Linkage)...), nil
}

type BTFDataSecType struct {
	commonType
	Variables []BTFDataSecVariable

	// Offset from the start of the types byte slice to the SizeType field
	sizeOffset int
}

func (t *BTFDataSecType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	var buf bytes.Buffer

	buf.Write((commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_DATASEC,
		VLen:     uint16(len(t.Variables)),
		sizeType: t.Size,
	}.ToBTFType(strTbl).ToBytes(order)))

	for _, v := range t.Variables {
		buf.Write(uint32sToBytes(
			order,
			uint32(v.Type.GetID()),
			v.Offset,
			v.Size,
		))
	}

	return buf.Bytes(), nil
}

type BTFDataSecVariable struct {
	Type   BTFType
	typeID uint32
	Offset uint32
	Size   uint32

	// Offset from the start of the types byte slice to the Offset field
	offsetOffset int
}

type BTFFloatType struct {
	commonType
}

func (t *BTFFloatType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_FLOAT,
		VLen:     0,
		sizeType: t.Size,
	}.ToBTFType(strTbl).ToBytes(order)), nil
}

// BTFDeclTagType The name_off encodes btf_decl_tag attribute string.
// The type should be struct, union, func, var or typedef.
// For var or typedef type, btf_decl_tag.component_idx must be -1.
// For the other three types, if the btf_decl_tag attribute is applied to the struct,
// union or func itself, btf_decl_tag.component_idx must be -1.
// Otherwise, the attribute is applied to a struct/union member or a func argument,
// and btf_decl_tag.component_idx should be a valid index (starting from 0) pointing to a member or an argument.
type BTFDeclTagType struct {
	commonType
	ComponentIdx uint32
}

func (t *BTFDeclTagType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	commonBytes := (commonType{
		Name:     t.Name,
		KindFlag: 0,
		Kind:     BTF_KIND_DECL_TAG,
		VLen:     0,
		sizeType: uint32(t.Type.GetID()),
	}.ToBTFType(strTbl).ToBytes(order))

	return append(commonBytes, uint32sToBytes(order, t.ComponentIdx)...), nil
}

// BTFVoidType is not an actual type in BTF, it is used as type ID 0.
type BTFVoidType struct{}

func (vt *BTFVoidType) GetID() int {
	return 0
}

func (vt *BTFVoidType) GetKind() BTFKind {
	return BTF_KIND_UNKN
}

func (vt *BTFVoidType) GetName() string {
	return ""
}

func (vt *BTFVoidType) Serialize(strTbl *StringTbl, order binary.ByteOrder) ([]byte, error) {
	return nil, nil
}

// BTFKind is an enum indicating what kind of type is indicated
type BTFKind uint8

const (
	// BTF_KIND_UNKN Unknown
	BTF_KIND_UNKN BTFKind = iota
	// BTF_KIND_INT Integer
	BTF_KIND_INT
	// BTF_KIND_PTR Pointer
	BTF_KIND_PTR
	// BTF_KIND_ARRAY Array
	BTF_KIND_ARRAY
	// BTF_KIND_STRUCT Struct
	BTF_KIND_STRUCT
	// BTF_KIND_UNION Union
	BTF_KIND_UNION
	// BTF_KIND_ENUM Enumeration
	BTF_KIND_ENUM
	// BTF_KIND_FWD Forward
	BTF_KIND_FWD
	// BTF_KIND_TYPEDEF Typedef
	BTF_KIND_TYPEDEF
	// BTF_KIND_VOLATILE Volatile
	BTF_KIND_VOLATILE
	// BTF_KIND_CONST Const
	BTF_KIND_CONST
	// BTF_KIND_RESTRICT Restrict
	BTF_KIND_RESTRICT
	// BTF_KIND_FUNC Function
	BTF_KIND_FUNC
	// BTF_KIND_FUNC_PROTO Function Proto
	BTF_KIND_FUNC_PROTO
	// BTF_KIND_VAR Variable
	BTF_KIND_VAR
	// BTF_KIND_DATASEC Section
	BTF_KIND_DATASEC
	// BTF_KIND_FLOAT Floating point
	BTF_KIND_FLOAT
	// BTF_KIND_DECL_TAG Decl Tag
	BTF_KIND_DECL_TAG

	// Not an actual value, must always be last in const block
	//nolint:deadcode,varcheck // used in unit test
	btfKindMax
)

var btfKindToStr = map[BTFKind]string{
	BTF_KIND_UNKN:       "Unknown",
	BTF_KIND_INT:        "Integer",
	BTF_KIND_PTR:        "Pointer",
	BTF_KIND_ARRAY:      "Array",
	BTF_KIND_STRUCT:     "Struct",
	BTF_KIND_UNION:      "Union",
	BTF_KIND_ENUM:       "Enumeration",
	BTF_KIND_FWD:        "Forward",
	BTF_KIND_TYPEDEF:    "Typedef",
	BTF_KIND_VOLATILE:   "Volatile",
	BTF_KIND_CONST:      "Const",
	BTF_KIND_RESTRICT:   "Restrict",
	BTF_KIND_FUNC:       "Function",
	BTF_KIND_FUNC_PROTO: "Proto function",
	BTF_KIND_VAR:        "Variable",
	BTF_KIND_DATASEC:    "Data section",
	BTF_KIND_FLOAT:      "Floating point",
	BTF_KIND_DECL_TAG:   "Decl tag",
}

func (bk BTFKind) String() string {
	return btfKindToStr[bk]
}

// The length of the Magic, Version, Flags, and HeaderLength fields
const commonLength = 8

// commonHeader is shared between the .BTF header and .BTF.ext header
type commonHeader struct {
	// Magic is always 0xeB9F, can be used to tell if the data is little or bigendian
	Magic     uint16
	byteOrder binary.ByteOrder
	// BTF version number
	Version uint8
	// Flags is unused (AFAIK)
	Flags uint8
	// HeaderLength is the size of this struct. Here for forwards/backwards compatibility since the size of this
	// header may change in the future.
	HeaderLength uint32
}

// Magic number of BTF
// https://elixir.bootlin.com/linux/v5.15.3/source/include/uapi/linux/btf.h#L8
const btfMagic = 0xEB9F

func parseCommonHeader(btf []byte) (commonHeader, uint32, error) {
	btfLen := len(btf)
	if btfLen < 8 {
		return commonHeader{}, 0, errors.New("not enough bytes to parse BTF header")
	}

	hdr := commonHeader{
		byteOrder: binary.LittleEndian,
	}
	off := 0

	read8 := func() uint8 {
		v := btf[off]
		off = off + 1
		return v
	}
	read32 := func() uint32 {
		v := hdr.byteOrder.Uint32(btf[off : off+4])
		off = off + 4
		return v
	}

	magic := hdr.byteOrder.Uint16(btf[off : off+2])
	// If the read magic number doesn't match, switch encoding
	if magic != btfMagic {
		hdr.byteOrder = binary.BigEndian

		// Read it again, if it still doesn't match the data is not right
		magic = hdr.byteOrder.Uint16(btf[off : off+2])
		if magic != btfMagic {
			return commonHeader{}, 0, errors.New("byte sequence doesn't contain valid BTF magic number")
		}
	}
	off += 2

	// Set outside init, since the code is order dependant, and I don't know if struct init happens in defined order.
	hdr.Version = read8()
	hdr.Flags = read8()
	hdr.HeaderLength = read32()

	return hdr, commonLength, nil
}

// btfHeader is the header of the ELF .BTF section
type btfHeader struct {
	commonHeader

	// The offset from the end of this header to the start of the type info
	TypeOffset uint32
	// The amount of bytes of type info there is
	TypeLength uint32
	// The offset for the end of this header to the start fo the strings
	StringOffset uint32
	// The length of the strings
	StringLength uint32
}

// parseBTFHeader parses the .BTF header of an ELF file, it returns the header, and the amount of bytes read.
// Or it resturn only an error.
func parseBTFHeader(btf []byte) (*btfHeader, uint32, error) {
	var err error
	hdr := btfHeader{}
	off := uint32(0)

	hdr.commonHeader, off, err = parseCommonHeader(btf)
	if err != nil {
		return nil, off, fmt.Errorf("parse common header: %w", err)
	}

	btfLen := len(btf)
	if btfLen < int(hdr.HeaderLength)-commonLength {
		return nil, off, errors.New("byte sequence smaller than indicated header size")
	}

	read32 := func() uint32 {
		v := hdr.byteOrder.Uint32(btf[off : off+4])
		off = off + 4
		return v
	}

	hdr.TypeOffset = read32()
	hdr.TypeLength = read32()
	hdr.StringOffset = read32()
	hdr.StringLength = read32()

	// Return slice of indicated length, in case it is longer than the struct we know
	return &hdr, hdr.HeaderLength, nil
}

// btfExtHeader is the header of the ELF .BTF.ext section
type btfExtHeader struct {
	commonHeader

	// The offset from the end of this header to the start of the func info
	FuncOffset uint32
	// The amount of bytes of func info there is
	FuncLength uint32
	// The offset for the end of this header to the start fo the lines
	LineOffset uint32
	// The length of the lines
	LineLength uint32
}

// parseBTFExtHeader parses the .BTF.ext header of an ELF File, it return the header and the amount of bytes read,
// or and error
func parseBTFExtHeader(btf []byte) (*btfExtHeader, uint32, error) {
	var err error
	hdr := btfExtHeader{}
	off := uint32(0)

	hdr.commonHeader, off, err = parseCommonHeader(btf)
	if err != nil {
		return nil, off, fmt.Errorf("parse common header: %w", err)
	}

	btfLen := len(btf)
	if btfLen < int(hdr.HeaderLength)-commonLength {
		return nil, off, errors.New("byte sequence smaller than indicated header size")
	}

	read32 := func() uint32 {
		v := hdr.byteOrder.Uint32(btf[off : off+4])
		off = off + 4
		return v
	}

	hdr.FuncOffset = read32()
	hdr.FuncLength = read32()
	hdr.LineOffset = read32()
	hdr.LineLength = read32()

	// Return slice of indicated length, in case it is longer than the struct we know
	return &hdr, hdr.HeaderLength, nil
}

// btfType is the type as you would find it on disk
type btfType struct {
	NameOffset uint32

	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-28: kind (e.g. int, ptr, array...etc)
	 * bits 29-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union and fwd
	 */
	Info uint32

	// SizeType is a union of "size" and "type"
	// "size" is used by INT, ENUM, STRUCT and UNION.
	// "size" tells the size of the type it is describing.
	//
	// "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	// FUNC, FUNC_PROTO and DECL_TAG.
	// "type" is a type_id referring to another type.
	//
	SizeType uint32
}

func (bt btfType) ToCommonType(strTbl *StringTbl) commonType {
	// TODO add links to clarify shifts and masks
	return commonType{
		Name:     strTbl.GetStringAtOffset(int(bt.NameOffset)),
		VLen:     uint16((bt.Info) & 0xffff),
		Kind:     BTFKind(((bt.Info) >> 24) & 0x1f),
		KindFlag: uint8(bt.Info >> 31),
		sizeType: bt.SizeType,
	}
}

func (bt btfType) ToBytes(order binary.ByteOrder) []byte {
	ret := make([]byte, 12)
	order.PutUint32(ret[0:4], bt.NameOffset)
	order.PutUint32(ret[4:8], bt.Info)
	order.PutUint32(ret[8:12], bt.SizeType)
	return ret
}

type commonType struct {
	Name     string
	VLen     uint16
	Kind     BTFKind
	KindFlag uint8
	Type     BTFType
	Size     uint32
	sizeType uint32
	TypeID   int
}

func (ct *commonType) GetKind() BTFKind {
	return ct.Kind
}

func (ct *commonType) GetID() int {
	return ct.TypeID
}

func (ct *commonType) GetName() string {
	return ct.Name
}

func (ct commonType) ToBTFType(strTbl *StringTbl) btfType {
	bt := btfType{
		NameOffset: uint32(strTbl.StrToOffset(ct.Name)),
		Info: (uint32(ct.KindFlag&0b00000001) << 31) |
			(uint32(ct.Kind&0x1f) << 24) |
			uint32(ct.VLen),
		SizeType: ct.sizeType,
	}
	return bt
}

func uint32sToBytes(bo binary.ByteOrder, ints ...uint32) []byte {
	b := make([]byte, 4*len(ints))
	for i := 0; i < len(ints); i++ {
		bo.PutUint32(b[i*4:(i+1)*4], ints[i])
	}
	return b
}
