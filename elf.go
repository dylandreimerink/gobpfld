package gobpfld

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

type ELFParseSettings struct {
	// If true, names which are to large will be truncated, this can cause unexpected behavior
	// Otherwise an error will be generated.
	TruncateNames bool
}

// BPFELF is the result of parsing an eBPF ELF file. It can contain multiple programs and maps.
type BPFELF struct {
	// Programs contained within the ELF
	Programs map[string]*BPFProgram
	// Maps defined in the ELF
	Maps map[string]*BPFGenericMap

	// eBPF code found in the .text section, often called "sub programs".
	// Used for library code and code shared by multiple programs by way of BPF to BPF calls
	txtInstr []ebpf.RawInstruction
	// A list of relocation tables by section name
	relTables map[string]ELFRelocTable
}

func LoadProgramFromELF(r io.ReaderAt, settings ELFParseSettings) (BPFELF, error) {
	var bpfElf BPFELF
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return bpfElf, err
	}

	if elfFile.Machine != elf.EM_BPF {
		return bpfElf, fmt.Errorf("elf file machine type is not BPF, machine type: '%s'", elfFile.Machine)
	}

	if elfFile.Class != elf.ELFCLASS64 {
		return bpfElf, fmt.Errorf("elf file class is not 64 bit, class: '%s'", elfFile.Class)
	}

	bpfElf, err = parseElf(elfFile, settings)
	if err != nil {
		return bpfElf, fmt.Errorf("processSectionsL %w", err)
	}

	for _, program := range bpfElf.Programs {
		progRelocTable, found := bpfElf.relTables[".rel"+program.Name.String()]
		if !found {
			continue
		}

		// The offset where main program instructions end and .text instructions start.
		txtInsOff := -1

		// If there is any code in the .text section
		if len(bpfElf.txtInstr) > 0 {
			// Check if this program uses any code from the .text section.
			// If there are multiple programs, not all may need the .text code, so adding it only increases
			// program size.
			//
			// TODO look into only adding the sub programs needed, not the while .text block (if doable)
			usesTxt := false
			for _, relocEntry := range progRelocTable {
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

		// Handle relocation entries which can incluse:
		//  - Map references(need to be resolved at load time)
		//  - BPF to BPF function calls (can be resolved here)
		for _, relocEntry := range progRelocTable {
			section := elfFile.Sections[relocEntry.Symbol.Section]
			if section.Name == ".text" {
				if txtInsOff == -1 {
					return bpfElf, fmt.Errorf("unable to relocate .text entry since it is empty")
				}

				absOff, err := relocEntry.AbsoluteOffset()
				if err != nil {
					return bpfElf, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
				}

				// Update the imm of the call instruction which points to a relocated function
				// in the .text section to reflect the current relative offset
				callInst := &program.Instructions[int(absOff)/ebpf.BPFInstSize]
				callInst.Imm = (int32(txtInsOff) + callInst.Imm) - (int32(absOff) / int32(ebpf.BPFInstSize))

				continue
			}

			if section.Name == "maps" {

				// The map name is the name of the symbol truncated to BPF_OBJ_NAME_LEN
				mapName := relocEntry.Symbol.Name
				if settings.TruncateNames && len(mapName) > bpftypes.BPF_OBJ_NAME_LEN-1 {
					mapName = mapName[:bpftypes.BPF_OBJ_NAME_LEN-1]
				}

				bpfMap, found := bpfElf.Maps[mapName]
				if !found {
					return bpfElf, fmt.Errorf("program references undefined map named '%s'", mapName)
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
					return bpfElf, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
				}
				relLocations = append(relLocations, absOff)

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
						return bpfElf, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
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

					bpfMap, found := bpfElf.Maps[mapName]
					if !found {
						return bpfElf, fmt.Errorf("program .text references undefined map named '%s'", mapName)
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
						return bpfElf, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
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

	return bpfElf, nil
}

// Parse the ELF file into the separate components which will need to be combined later
func parseElf(
	elfFile *elf.File,
	settings ELFParseSettings,
) (
	bpfElf BPFELF,
	err error,
) {
	bpfElf = BPFELF{
		Programs:  map[string]*BPFProgram{},
		Maps:      map[string]*BPFGenericMap{},
		relTables: map[string]ELFRelocTable{},
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

			// Primary eBPF code sections are not prefixed with a .
			if strings.HasPrefix(section.Name, ".") {
				// Ignore the section, unless it is the .text section which contains additional/shared eBPF code
				if section.Name != ".text" {
					continue
				}
			}

			data, err := section.Data()
			if err != nil {
				return bpfElf, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
			}

			if section.Name == "license" {
				license = CStrBytesToString(data)
				continue
			}

			if section.Name == "maps" {
				// If section flag does not have alloc, its not a proper map def
				if section.Flags&elf.SHF_ALLOC == 0 {
					// TODO Maybe error here?
					continue
				}

				for i := 0; i < len(data); i += BPFMapDefSize {
					bpfMap := &BPFGenericMap{
						AbstractMap: AbstractMap{
							Definition: BPFMapDef{
								Type:       bpftypes.BPFMapType(elfFile.ByteOrder.Uint32(data[i : i+4])),
								KeySize:    elfFile.ByteOrder.Uint32(data[i+4 : i+8]),
								ValueSize:  elfFile.ByteOrder.Uint32(data[i+8 : i+12]),
								MaxEntries: elfFile.ByteOrder.Uint32(data[i+12 : i+16]),
								Flags:      bpftypes.BPFMapFlags(elfFile.ByteOrder.Uint32(data[i+16 : i+20])),
							},
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

						err = bpfMap.Name.SetString(symbol.Name)
						if err != nil {
							if settings.TruncateNames && errors.Is(err, ErrObjNameToLarge) {
								err = bpfMap.Name.SetString(symbol.Name[:bpftypes.BPF_OBJ_NAME_LEN-1])
								if err != nil {
									return bpfElf, fmt.Errorf("failed to truncate map name: %w", err)
								}
							} else {
								return bpfElf, fmt.Errorf("failed to set map name: %w", err)
							}
						}

						break
					}

					if bpfMap.Name.String() == "" {
						return bpfElf, fmt.Errorf(
							"unable to find name in symbol table for map at index %d in section '%s'",
							i,
							section.Name,
						)
					}

					// TODO map name duplicate check

					bpfElf.Maps[bpfMap.Name.String()] = bpfMap
				}

				continue
			}

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

			// For other sections, create it as a seperate program

			program := NewBPFProgram()
			program.Instructions = instructions
			err = program.Name.SetString(section.Name)
			if err != nil {
				if settings.TruncateNames && errors.Is(err, ErrObjNameToLarge) {
					err = program.Name.SetString(section.Name[:bpftypes.BPF_OBJ_NAME_LEN-1])
					if err != nil {
						return bpfElf, fmt.Errorf("failed to truncate program name: %w", err)
					}
				} else {
					return bpfElf, fmt.Errorf("failed to set program name: %w", err)
				}
			}

			bpfElf.Programs[program.Name.String()] = program

		case elf.SHT_REL:
			// Relocation table

			data, err := section.Data()
			if err != nil {
				return bpfElf, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
			}

			if len(data)%16 != 0 {
				return bpfElf, fmt.Errorf("size of relocation table '%s' not devisable by 16", section.Name)
			}

			relTable := make(ELFRelocTable, len(data)/16)
			for i := 0; i < len(data); i += 16 {
				entry := ELFRelocEntry{
					Rel64: elf.Rel64{
						Off:  elfFile.ByteOrder.Uint64(data[i : i+8]),
						Info: elfFile.ByteOrder.Uint64(data[i+8 : i+16]),
					},
				}
				symNum := elf.R_SYM64(entry.Info)
				if uint32(len(symbols)) < symNum {
					return bpfElf, fmt.Errorf("symbol number in relocation table '%s' does not exist in symbol table", section.Name)
				}

				entry.Symbol = &symbols[symNum-1]
				entry.Type = ELF_R_BPF(elf.R_TYPE64(entry.Info))

				relTable[i/16] = entry
			}

			bpfElf.relTables[section.Name] = relTable
		}
	}

	// Since the licence section may come after a program section, set the license for each program after all sections
	// are parsed.
	for _, program := range bpfElf.Programs {
		program.Licence = license
	}

	return bpfElf, nil
}

type ELFRelocTable []ELFRelocEntry

// The BPF ELF reloc types for BPF.
// https://github.com/llvm/llvm-project/blob/74d9a76ad3f55c16982ceaa8b6b4a6b7744109b1/llvm/include/llvm/BinaryFormat/ELFRelocs/BPF.def
type ELF_R_BPF int

const (
	R_BPF_NONE  ELF_R_BPF = 0
	R_BPF_64_64 ELF_R_BPF = 1
	R_BPF_64_32 ELF_R_BPF = 10
)

type ELFRelocEntry struct {
	elf.Rel64

	Symbol *elf.Symbol
	Type   ELF_R_BPF
}

func (e *ELFRelocEntry) AbsoluteOffset() (uint64, error) {
	switch e.Type {
	case R_BPF_64_64:
		// Just the absolute offset from the begining of the program section
		return e.Off, nil
	case R_BPF_64_32:
		// Just the absolute offset from the begining of the program section truncated to 32 bits
		return e.Off & 0x00000000FFFFFFFF, nil
	}

	return 0, fmt.Errorf("reloc type not implemented: '%d'", e.Type)
}
