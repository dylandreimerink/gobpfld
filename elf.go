package gobpfld

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/dylandreimerink/gobpfld/perf"
)

type ELFParseSettings struct {
	// If true, names which are to large will be truncated, this can cause unexpected behavior
	// Otherwise an error will be generated.
	TruncateNames bool
}

// BPFELF is the result of parsing an eBPF ELF file. It can contain multiple programs and maps.
type BPFELF struct {
	// Programs contained within the ELF
	Programs map[string]BPFProgram
	// Maps defined in the ELF
	Maps map[string]BPFMap
	BTF  *BTF
}

type bpfELF struct {
	// Programs contained within the ELF
	Programs map[string]*elfBPFProgram
	// Maps defined in the ELF
	Maps map[string]AbstractMap
	BTF  *BTF

	// eBPF code found in the .text section, often called "sub programs".
	// Used for library code and code shared by multiple programs by way of BPF to BPF calls
	txtInstr []ebpf.RawInstruction
	// A list of relocation tables by section name
	relTables map[string]elfRelocTable

	// Store the data of the .BTF.ext section, since we need to parse it after
	// the .BTF section.
	btfExtBytes []byte
}

type elfBPFProgram struct {
	AbstractBPFProgram

	// The ELF section where the program came from
	section string
	// The offset from the start of the section to the start of the program in bytes.
	offset int
	// The size of the program code in bytes, which is not always the size of the instructions slice
	// due to bpf_to_bpf linking
	size int
}

func LoadProgramFromELF(r io.ReaderAt, settings ELFParseSettings) (BPFELF, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return BPFELF{}, err
	}

	if elfFile.Machine != elf.EM_BPF {
		return BPFELF{}, fmt.Errorf("elf file machine type is not BPF, machine type: '%s'", elfFile.Machine)
	}

	if elfFile.Class != elf.ELFCLASS64 {
		return BPFELF{}, fmt.Errorf("elf file class is not 64 bit, class: '%s'", elfFile.Class)
	}

	bpfElf, err := parseElf(elfFile, settings)
	if err != nil {
		return BPFELF{}, fmt.Errorf("processSections: %w", err)
	}

	// TODO process BTF relocations (Look into this, relocation entries don't seem to make sense for .rel.BTF)
	//   https://patchwork.ozlabs.org/project/netdev/patch/20190807214001.872988-4-andriin@fb.com/
	// TODO recalculate BTF func and line instruction offsets after all sections have been combined

	// Add BTF info to the abstract maps and resolve the actual map type, to be used during map loading.
	bpfMaps := make(map[string]BPFMap)
	for name, bpfMap := range bpfElf.Maps {
		bpfMap.BTF = bpfElf.BTF
		if bpfElf.BTF != nil {
			bpfMap.BTFMapType = bpfElf.BTF.typesByName[name]
		}

		bpfMaps[name] = bpfMapFromAbstractMap(bpfMap)
	}

	// Index lines and funcs by section since we will be relocating per section
	btfLinesPerSection := make(map[string][]BTFLine)
	btfFuncsPerSection := make(map[string][]BTFFunc)
	if bpfElf.BTF != nil {
		for _, line := range bpfElf.BTF.lines {
			lines := btfLinesPerSection[line.Section]
			lines = append(lines, line)
			btfLinesPerSection[line.Section] = lines
		}
		for _, f := range bpfElf.BTF.funcs {
			funcs := btfFuncsPerSection[f.Section]
			funcs = append(funcs, f)
			btfFuncsPerSection[f.Section] = funcs
		}
	}

	for _, program := range bpfElf.Programs {
		progRelocTable, found := bpfElf.relTables[".rel"+program.section]
		if !found {
			continue
		}

		// The offset where main program instructions ends and .text instructions start.
		txtInsOff := -1

		// If there is any code in the .text section
		if len(bpfElf.txtInstr) > 0 {
			// Check if this program uses any code from the .text section.
			// If there are multiple programs, not all may need the .text code.
			// Adding it causes the verifier to throw dead code errors.
			//
			// TODO look into only adding the sub programs needed, not the whole .text block (if doable)
			//  if there is dead-code the verifier will refuse to load, so this might be a good feature.
			usesTxt := false
			for _, relocEntry := range progRelocTable {
				// The absolute offset from the start of the section to the location where the entry should be linked
				absOff, err := relocEntry.AbsoluteOffset()
				if err != nil {
					return BPFELF{}, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
				}

				// Calculate the offset from the start of the program within a section
				progOff := int(absOff) - program.offset

				// If the relocation entry is for before or after a current program (another program in the same
				// section). Ignore it.
				if progOff < 0 || progOff >= program.size {
					continue
				}

				if elfFile.Sections[int(relocEntry.Symbol.Section)].Name == ".text" {
					usesTxt = true
					break
				}
			}

			if usesTxt {
				// Make a new instructions slice which can hold the main instruction and .text instructions
				newInst := make([]ebpf.RawInstruction, len(program.Instructions)+len(bpfElf.txtInstr))
				txtInsOff = copy(newInst, program.Instructions)
				copy(newInst[txtInsOff:], bpfElf.txtInstr)
				program.Instructions = newInst
			}
		}

		for _, progLines := range btfLinesPerSection[program.section] {
			line := progLines.ToKernel()
			// The offsets in ELF are in bytes from section start, for the kernel we need the offset of instructions
			// Since the program is at the top, we can just divide by the instruction size.
			line.InstructionOffset = line.InstructionOffset / uint32(ebpf.BPFInstSize)
			program.BTFLines = append(program.BTFLines, line)
		}
		for _, progFuncs := range btfFuncsPerSection[program.section] {
			f := progFuncs.ToKernel()
			// The offsets in ELF are in bytes from section start, for the kernel we need the offset of instructions
			// Since the program is at the top, we can just divide by the instruction size.
			f.InstructionOffset = f.InstructionOffset / uint32(ebpf.BPFInstSize)
			program.BTFFuncs = append(program.BTFFuncs, f)
		}
		if txtInsOff != -1 {
			for _, textLine := range btfLinesPerSection[".text"] {
				line := textLine.ToKernel()
				// The offsets in ELF are in bytes from section start, for the kernel we need the offset of instructions
				// Divide to offset within the .text section by instruction size and add the txtInsOff to get
				// the correct absolute instruction offset.
				line.InstructionOffset = (line.InstructionOffset / uint32(ebpf.BPFInstSize)) + uint32(txtInsOff)
				program.BTFLines = append(program.BTFLines, line)
			}
			for _, textFunc := range btfFuncsPerSection[".text"] {
				f := textFunc.ToKernel()
				// The offsets in ELF are in bytes from section start, for the kernel we need the offset of instructions
				// Divide to offset within the .text section by instruction size and add the txtInsOff to get
				// the correct absolute instruction offset.
				f.InstructionOffset = (f.InstructionOffset / uint32(ebpf.BPFInstSize)) + uint32(txtInsOff)
				program.BTFFuncs = append(program.BTFFuncs, f)
			}
		}

		// Handle relocation entries which can includes:
		//  - Map references(need to be resolved at load time)
		//  - BPF to BPF function calls (can be resolved here)
		for _, relocEntry := range progRelocTable {
			section := elfFile.Sections[relocEntry.Symbol.Section]

			// The absolute offset from the start of the section to the location where the entry should be linked
			absOff, err := relocEntry.AbsoluteOffset()
			if err != nil {
				return BPFELF{}, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
			}

			// Calculate the offset from the start of the program within a section
			progOff := int(absOff) - program.offset

			// If the relocation entry is for before or after a current program (another program in the same section)
			// Ignore it.
			if progOff < 0 || progOff >= program.size {
				continue
			}

			if section.Name == ".text" {
				if txtInsOff == -1 {
					return BPFELF{}, fmt.Errorf("unable to relocate .text entry since it is empty")
				}

				// Update the imm of the call instruction which points to a relocated function
				// in the .text section to reflect the current relative offset
				callInst := &program.Instructions[progOff/ebpf.BPFInstSize]
				callInst.Imm = (int32(txtInsOff) + callInst.Imm) - (int32(progOff) / int32(ebpf.BPFInstSize))

				continue
			}

			if section.Name == "maps" {
				// The map name is the name of the symbol truncated to BPF_OBJ_NAME_LEN
				mapName := relocEntry.Symbol.Name
				if settings.TruncateNames && len(mapName) > bpftypes.BPF_OBJ_NAME_LEN-1 {
					mapName = mapName[:bpftypes.BPF_OBJ_NAME_LEN-1]
				}

				bpfMap, found := bpfMaps[mapName]
				if !found {
					return BPFELF{}, fmt.Errorf("program references undefined map named '%s'", mapName)
				}

				// Add map to list of maps used by program if not already in list
				_, found = program.Maps[mapName]
				if !found {
					program.Maps[mapName] = bpfMap
				}

				relLocations := program.MapFDLocations[mapName]
				if relLocations == nil {
					relLocations = []uint64{}
				}

				relLocations = append(relLocations, uint64(progOff))

				program.MapFDLocations[mapName] = relLocations
			}
		}

		// If this program has the .text section appended, we need to resolve any map relocations from that section
		if txtInsOff != -1 {
			txtRelocTable, found := bpfElf.relTables[".rel.text"]
			if !found {
				continue
			}

			for _, relocEntry := range txtRelocTable {
				section := elfFile.Sections[relocEntry.Symbol.Section]

				if section.Name == ".text" {
					absOff, err := relocEntry.AbsoluteOffset()
					if err != nil {
						return BPFELF{}, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
					}

					// Update the imm of the call instruction which points to a relocated function
					// in the .text section to reflect the current relative offset
					callInst := &program.Instructions[txtInsOff+int(absOff)/ebpf.BPFInstSize]
					callInst.Imm = (int32(txtInsOff) + callInst.Imm) - (int32(absOff) / int32(ebpf.BPFInstSize))

					continue
				}

				if section.Name == "maps" {
					mapName := relocEntry.Symbol.Name
					if settings.TruncateNames && len(mapName) > bpftypes.BPF_OBJ_NAME_LEN-1 {
						mapName = mapName[:bpftypes.BPF_OBJ_NAME_LEN-1]
					}

					bpfMap, found := bpfMaps[mapName]
					if !found {
						return BPFELF{}, fmt.Errorf("program .text references undefined map named '%s'", mapName)
					}

					// Add map to list of maps used by program if not already in list
					_, found = program.Maps[mapName]
					if !found {
						program.Maps[mapName] = bpfMap
					}

					relLocations := program.MapFDLocations[mapName]
					if relLocations == nil {
						relLocations = []uint64{}
					}

					absOff, err := relocEntry.AbsoluteOffset()
					if err != nil {
						return BPFELF{}, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
					}

					// Since the .text section is appended to the main program and the relocation offset is relative
					// to the start of the .text section we need to add to offset of the .text instructions to the
					// absolute address.
					absOff += uint64(txtInsOff * ebpf.BPFInstSize)

					relLocations = append(relLocations, absOff)

					program.MapFDLocations[mapName] = relLocations
				}
			}
		}
	}

	retBpfELF := BPFELF{
		Maps:     bpfMaps,
		Programs: make(map[string]BPFProgram),
		BTF:      bpfElf.BTF,
	}

	for name, prog := range bpfElf.Programs {
		specificProgInt := BPFProgramFromAbstract(prog.AbstractBPFProgram)

		sectionParts := strings.Split(prog.section, "/")

		// For some program types the section name can be used to pass additional information about
		// how the program should be attached
		switch specificProg := specificProgInt.(type) {
		case *ProgramTracepoint:
			if len(sectionParts) >= 2 {
				specificProg.DefaultCategory = sectionParts[1]
			}
			if len(sectionParts) >= 3 {
				specificProg.DefaultName = sectionParts[2]
			}

		case *ProgramKProbe:
			uprobe := false
			switch sectionParts[0] {
			case "kprobe":
				specificProg.DefaultType = perf.TypeKProbe
			case "kretprobe":
				specificProg.DefaultType = perf.TypeKRetprobe
			case "uprobe":
				uprobe = true
				specificProg.DefaultType = perf.TypeUProbe
			case "uretprobe":
				uprobe = true
				specificProg.DefaultType = perf.TypeURetProbe
			}

			if uprobe {
				var path, offsetStr string
				if len(sectionParts) == 2 {
					path = "/" + sectionParts[1]
				}

				if len(sectionParts) == 3 {
					path = "/" + sectionParts[1]
					offsetStr = sectionParts[2]
				}

				if len(sectionParts) > 3 {
					path = "/" + strings.Join(sectionParts[1:len(sectionParts)-1], "/")
					offsetStr = sectionParts[len(sectionParts)-1]
				}

				specificProg.DefaultPath = path
				if off, err := strconv.ParseInt(offsetStr, 0, 64); err == nil {
					specificProg.DefaultOffset = int(off)
				}

			} else {
				specificProg.DefaultEvent = name
				if len(sectionParts) == 2 {
					specificProg.DefaultSymbol = sectionParts[1]
				}
				if len(sectionParts) >= 3 {
					specificProg.DefaultModule = sectionParts[1]
					specificProg.DefaultSymbol = sectionParts[2]
				}
			}
		}

		retBpfELF.Programs[name] = specificProgInt
	}

	return retBpfELF, nil
}

// Parse the ELF file into the separate components which will need to be combined later
func parseElf(
	elfFile *elf.File,
	settings ELFParseSettings,
) (
	bpfElf bpfELF,
	err error,
) {
	bpfElf = bpfELF{
		Programs:  map[string]*elfBPFProgram{},
		Maps:      map[string]AbstractMap{},
		relTables: map[string]elfRelocTable{},
	}

	symbols, err := elfFile.Symbols()
	if err != nil {
		return bpfElf, fmt.Errorf("error while getting symbols from ELF file: %w", err)
	}

	license := "Unknown"

	for sectionIndex, section := range elfFile.Sections {
		switch section.Type {
		case elf.SHT_PROGBITS:
			// Program data

			data, err := section.Data()
			if err != nil {
				return bpfElf, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
			}

			switch section.Name {
			case "license":
				license = CStrBytesToString(data)
				continue

			case "maps":
				// If section flag does not have alloc, its not a proper map def
				if section.Flags&elf.SHF_ALLOC == 0 {
					// TODO Maybe error here?
					continue
				}

				for i := 0; i < len(data); i += bpfMapDefSize {
					abstractMap := AbstractMap{
						Definition: BPFMapDef{
							Type:       bpftypes.BPFMapType(elfFile.ByteOrder.Uint32(data[i : i+4])),
							KeySize:    elfFile.ByteOrder.Uint32(data[i+4 : i+8]),
							ValueSize:  elfFile.ByteOrder.Uint32(data[i+8 : i+12]),
							MaxEntries: elfFile.ByteOrder.Uint32(data[i+12 : i+16]),
							Flags:      bpftypes.BPFMapFlags(elfFile.ByteOrder.Uint32(data[i+16 : i+20])),
						},
					}

					for _, symbol := range symbols {
						// If the symbol isn't for this section
						if int(symbol.Section) != sectionIndex {
							continue
						}

						// if the symbol is not for the current data offset
						if symbol.Value != uint64(i) {
							continue
						}

						err = abstractMap.Name.SetString(symbol.Name)
						if err != nil {
							if settings.TruncateNames && errors.Is(err, ErrObjNameToLarge) {
								err = abstractMap.Name.SetString(symbol.Name[:bpftypes.BPF_OBJ_NAME_LEN-1])
								if err != nil {
									return bpfElf, fmt.Errorf("failed to truncate map name: %w", err)
								}
							} else {
								return bpfElf, fmt.Errorf("failed to set map name: %w", err)
							}
						}

						break
					}

					if abstractMap.Name.String() == "" {
						return bpfElf, fmt.Errorf(
							"unable to find name in symbol table for map at index %d in section '%s'",
							i,
							section.Name,
						)
					}

					// TODO map name duplicate check

					bpfElf.Maps[abstractMap.Name.String()] = abstractMap
				}

				continue

			case ".BTF":
				// BTF type and string information

				if bpfElf.BTF == nil {
					bpfElf.BTF = NewBTF()
				}

				err := bpfElf.BTF.ParseBTF(data)
				if err != nil {
					return bpfElf, fmt.Errorf("parse .BTF: %w", err)
				}

				continue
			case ".BTF.ext":
				// BTF line and function information

				bpfElf.btfExtBytes = data

				continue

			// TODO parse .BTF_ids (Used to identify specific types in the kernel for tracing etc.)
			default:

				// Assume program

				// If the section flags don't indicate it contains instructions, it not a program
				if section.Flags&elf.SHF_EXECINSTR == 0 {
					// TODO Maybe error here?
					continue
				}

				if len(data)%ebpf.BPFInstSize != 0 {
					return bpfElf, fmt.Errorf("elf section is incorrect size for BPF program, should be divisible by 8")
				}

				instructions := make([]ebpf.RawInstruction, len(data)/ebpf.BPFInstSize)
				for i := 0; i < len(data); i += ebpf.BPFInstSize {
					instructions[i/ebpf.BPFInstSize] = ebpf.RawInstruction{
						Op:  data[i],
						Reg: data[i+1],
						Off: int16(elfFile.ByteOrder.Uint16(data[i+2 : i+4])),
						Imm: int32(elfFile.ByteOrder.Uint32(data[i+4 : i+8])),
					}
				}

				// If this is the .text section, save the instructions in a sperate slice without a program struct
				if section.Name == ".text" {
					bpfElf.txtInstr = instructions
					continue
				}

				// For other sections, create it as a separate program

				globalFunctions := make([]elf.Symbol, 0)

				// Find the name of the program / function name.
				// We are looking for a global functions
				for _, sym := range symbols {
					if sym.Section != elf.SectionIndex(sectionIndex) {
						continue
					}

					if elf.ST_BIND(sym.Info) != elf.STB_GLOBAL || elf.ST_TYPE(sym.Info) != elf.STT_FUNC {
						continue
					}

					globalFunctions = append(globalFunctions, sym)
				}

				sectionParts := strings.Split(section.Name, "/")
				progType := sectionNameToProgType[sectionParts[0]]

				if progType == bpftypes.BPF_PROG_TYPE_UNSPEC {
					return bpfELF{}, fmt.Errorf(
						"unknown elf section '%s', doesn't match any eBPF program type",
						sectionParts[0],
					)
				}

				for i := 0; i < len(globalFunctions); i++ {
					sym := globalFunctions[i]

					program := NewAbstractBPFProgram()
					program.ProgramType = progType
					start := int(sym.Value) / ebpf.BPFInstSize
					end := (int(sym.Value) + int(sym.Size)) / ebpf.BPFInstSize
					program.Instructions = instructions[start:end]

					err = program.Name.SetString(sym.Name)
					if err != nil {
						if settings.TruncateNames && errors.Is(err, ErrObjNameToLarge) {
							err = program.Name.SetString(sym.Name[:bpftypes.BPF_OBJ_NAME_LEN-1])
							if err != nil {
								return bpfElf, fmt.Errorf("failed to truncate program name: %w", err)
							}
						} else {
							return bpfElf, fmt.Errorf("failed to set program name '%s': %w", sym.Name, err)
						}
					}

					bpfElf.Programs[sym.Name] = &elfBPFProgram{
						AbstractBPFProgram: program,
						section:            section.Name,
						offset:             int(sym.Value),
						size:               int(sym.Size),
					}
				}
			}

		case elf.SHT_REL:
			// Relocation table

			data, err := section.Data()
			if err != nil {
				return bpfElf, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
			}

			if len(data)%16 != 0 {
				return bpfElf, fmt.Errorf("size of relocation table '%s' not devisable by 16", section.Name)
			}

			relTable := make(elfRelocTable, len(data)/16)
			for i := 0; i < len(data); i += 16 {
				entry := elfRelocEntry{
					Rel64: elf.Rel64{
						Off:  elfFile.ByteOrder.Uint64(data[i : i+8]),
						Info: elfFile.ByteOrder.Uint64(data[i+8 : i+16]),
					},
				}
				symNum := elf.R_SYM64(entry.Info)
				if uint32(len(symbols)) < symNum {
					return bpfElf, fmt.Errorf(
						"symbol number in relocation table '%s' does not exist in symbol table",
						section.Name,
					)
				}

				entry.Symbol = &symbols[symNum-1]
				entry.Type = elf_r_bpf(elf.R_TYPE64(entry.Info))

				relTable[i/16] = entry
			}

			bpfElf.relTables[section.Name] = relTable
		}
	}

	// If set, parse the .BTF.ext section now, since we have to guarantee it happens after
	// BTF parsing since the Ext uses the string table and types from the main section.
	if bpfElf.btfExtBytes != nil {
		if bpfElf.BTF == nil {
			bpfElf.BTF = NewBTF()
		}

		err := bpfElf.BTF.ParseBTFExt(bpfElf.btfExtBytes)
		if err != nil {
			return bpfElf, fmt.Errorf("parse .BTF.ext: %w", err)
		}
	}

	// Patch total Size of DataSec types, and offsets for the individual variables
	for _, btfType := range bpfElf.BTF.Types {
		dataSec, ok := btfType.(*BTFDataSecType)
		if !ok {
			continue
		}

		section := elfFile.Section(dataSec.Name)
		if section != nil {
			sizeType := bpfElf.BTF.rawType[dataSec.sizeOffset : dataSec.sizeOffset+4]
			bpfElf.BTF.btfHdr.byteOrder.PutUint32(sizeType, uint32(section.Size))

			for _, variable := range dataSec.Variables {
				for _, sym := range symbols {
					// Ignore any symbols which are not for the current section
					if len(elfFile.Sections) <= int(sym.Section) || elfFile.Sections[sym.Section] != section {
						continue
					}

					// The symbols name must match the name of the DataSec variable type
					if sym.Name != variable.Type.GetName() {
						continue
					}

					// The value of the symbol is the offset from the start of the section
					offset := bpfElf.BTF.rawType[variable.offsetOffset : variable.offsetOffset+4]
					bpfElf.BTF.btfHdr.byteOrder.PutUint32(offset, uint32(sym.Value))
					break
				}
			}
		}
	}

	// Since the license section may come after a program section, set the license for each program after all sections
	// are parsed.
	for _, program := range bpfElf.Programs {
		program.License = license
		program.BTF = bpfElf.BTF
	}

	return bpfElf, nil
}

// This map translates ELF section names to program types.
// https://github.com/libbpf/libbpf/blob/eaea2bce024fa6ae0db54af1e78b4d477d422791/src/libbpf.c#L8270
var sectionNameToProgType = map[string]bpftypes.BPFProgType{
	"sock_filter":             bpftypes.BPF_PROG_TYPE_SOCKET_FILTER,
	"socket":                  bpftypes.BPF_PROG_TYPE_SOCKET_FILTER,
	"kprobe":                  bpftypes.BPF_PROG_TYPE_KPROBE,
	"kretprobe":               bpftypes.BPF_PROG_TYPE_KPROBE,
	"uprobe":                  bpftypes.BPF_PROG_TYPE_KPROBE,
	"uretprobe":               bpftypes.BPF_PROG_TYPE_KPROBE,
	"tc_cls":                  bpftypes.BPF_PROG_TYPE_SCHED_CLS,
	"tc_act":                  bpftypes.BPF_PROG_TYPE_SCHED_ACT,
	"tracepoint":              bpftypes.BPF_PROG_TYPE_TRACEPOINT,
	"xdp":                     bpftypes.BPF_PROG_TYPE_XDP,
	"perf_event":              bpftypes.BPF_PROG_TYPE_PERF_EVENT,
	"cgroup_skb":              bpftypes.BPF_PROG_TYPE_CGROUP_SKB,
	"cgroup_sock":             bpftypes.BPF_PROG_TYPE_CGROUP_SOCK,
	"lwt_in":                  bpftypes.BPF_PROG_TYPE_LWT_IN,
	"lwt_out":                 bpftypes.BPF_PROG_TYPE_LWT_OUT,
	"lwt_xmit":                bpftypes.BPF_PROG_TYPE_LWT_XMIT,
	"sock_opts":               bpftypes.BPF_PROG_TYPE_SOCK_OPS,
	"sk_skb":                  bpftypes.BPF_PROG_TYPE_SK_SKB,
	"cgroup_device":           bpftypes.BPF_PROG_TYPE_CGROUP_DEVICE,
	"raw_tracepoint":          bpftypes.BPF_PROG_TYPE_RAW_TRACEPOINT,
	"cgroup_sock_addr":        bpftypes.BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	"lwt_seg6local":           bpftypes.BPF_PROG_TYPE_LWT_SEG6LOCAL,
	"lirc_mode2":              bpftypes.BPF_PROG_TYPE_LIRC_MODE2,
	"sk_reuseport":            bpftypes.BPF_PROG_TYPE_SK_REUSEPORT,
	"flow_dissector":          bpftypes.BPF_PROG_TYPE_FLOW_DISSECTOR,
	"cgroup_sysctl":           bpftypes.BPF_PROG_TYPE_CGROUP_SYSCTL,
	"raw_tracepoint_writable": bpftypes.BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	"cgroup_sockopt":          bpftypes.BPF_PROG_TYPE_CGROUP_SOCKOPT,
	"tracing":                 bpftypes.BPF_PROG_TYPE_TRACING,
	"struct_ops":              bpftypes.BPF_PROG_TYPE_STRUCT_OPS,
	"ext":                     bpftypes.BPF_PROG_TYPE_EXT,
	"lsm":                     bpftypes.BPF_PROG_TYPE_LSM,
	"sk_lookup":               bpftypes.BPF_PROG_TYPE_SK_LOOKUP,
	"syscall":                 bpftypes.BPF_PROG_TYPE_SYSCALL,
}

type elfRelocTable []elfRelocEntry

// elf_r_bpf The BPF ELF reloc types for BPF.
// https://github.com/llvm/llvm-project/blob/74d9a76ad3f55c16982ceaa8b6b4a6b7744109b1/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def
//nolint:lll
type elf_r_bpf int

const (
	// r_bpf_none is an invalid relocation type
	//nolint:deadcode,varcheck // want to keep this here for completeness
	r_bpf_none elf_r_bpf = 0
	// r_bpf_64_64 indicates that 32 bits should be relocated
	r_bpf_64_64 elf_r_bpf = 1
	// r_bpf_64_32 insicates that 64 bits should be relocated
	r_bpf_64_32 elf_r_bpf = 10
)

type elfRelocEntry struct {
	elf.Rel64

	Symbol *elf.Symbol
	Type   elf_r_bpf
}

func (e *elfRelocEntry) AbsoluteOffset() (uint64, error) {
	switch e.Type {
	case r_bpf_64_64:
		// Just the absolute offset from the beginning of the program section
		return e.Off, nil
	case r_bpf_64_32:
		// Just the absolute offset from the beginning of the program section truncated to 32 bits
		const _32bitMask = 0x00000000FFFFFFFF
		return e.Off & _32bitMask, nil
	}

	return 0, fmt.Errorf("reloc type not implemented: '%d'", e.Type)
}
