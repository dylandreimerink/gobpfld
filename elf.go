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

func LoadProgramFromELF(r io.ReaderAt, settings ELFParseSettings) (map[string]*BPFProgram, error) {
	elfFile, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	if elfFile.Machine != elf.EM_BPF {
		return nil, fmt.Errorf("elf file machine type is not BPF, machine type: '%s'", elfFile.Machine)
	}

	if elfFile.Class != elf.ELFCLASS64 {
		return nil, fmt.Errorf("elf file class is not 64 bit, class: '%s'", elfFile.Class)
	}

	license := "Unknown"

	programs := map[string]*BPFProgram{}
	bpfMaps := map[string]*BPFGenericMap{}
	relTables := map[string]ELFRelocTable{}

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("error while getting symbols from ELF file: %w", err)
	}

	for sectionIndex, section := range elfFile.Sections {
		switch section.Type {
		case elf.SHT_PROGBITS:
			// Program data

			// If name is prefixed with a . it is metadata
			if strings.HasPrefix(section.Name, ".") {
				// ignore for now
				continue
			}

			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
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
									return nil, fmt.Errorf("failed to truncate map name: %w", err)
								}
							} else {
								return nil, fmt.Errorf("failed to set map name: %w", err)
							}
						}

						break
					}

					if bpfMap.Name.String() == "" {
						return nil, fmt.Errorf(
							"unable to find name in symbol table for map at index %d in section '%s'",
							i,
							section.Name,
						)
					}

					// TODO map name duplicate check

					bpfMaps[bpfMap.Name.String()] = bpfMap
				}

				continue
			}

			// Assume program

			// If the section flags don't indicate it contains instructions, it not a program
			if section.Flags&elf.SHF_EXECINSTR == 0 {
				// TODO Maybe error here?
				continue
			}

			program := NewBPFProgram()
			err = program.Name.SetString(section.Name)
			if err != nil {
				if settings.TruncateNames && errors.Is(err, ErrObjNameToLarge) {
					err = program.Name.SetString(section.Name[:bpftypes.BPF_OBJ_NAME_LEN-1])
					if err != nil {
						return nil, fmt.Errorf("failed to truncate program name: %w", err)
					}
				} else {
					return nil, fmt.Errorf("failed to set program name: %w", err)
				}
			}

			if len(data)%ebpf.BPFInstSize != 0 {
				return nil, fmt.Errorf("elf section is incorrect size for BPF program, should be divisible by 8")
			}

			program.Instructions = make([]ebpf.RawInstruction, len(data)/ebpf.BPFInstSize)
			for i := 0; i < len(data); i += ebpf.BPFInstSize {
				program.Instructions[i/ebpf.BPFInstSize] = ebpf.RawInstruction{
					Op:  data[i],
					Reg: data[i+1],
					Off: int16(elfFile.ByteOrder.Uint16(data[i+2 : i+4])),
					Imm: int32(elfFile.ByteOrder.Uint32(data[i+4 : i+8])),
				}
			}

			programs[program.Name.String()] = program

		case elf.SHT_REL:
			// Relocation table

			data, err := section.Data()
			if err != nil {
				return nil, fmt.Errorf("error while loading section '%s': %w", section.Name, err)
			}

			if len(data)%16 != 0 {
				return nil, fmt.Errorf("size of relocation table '%s' not devisable by 16", section.Name)
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
					return nil, fmt.Errorf("symbol number in relocation table '%s' does not exist in symbol table", section.Name)
				}

				entry.Symbol = &symbols[symNum-1]
				entry.Type = ELF_R_BPF(elf.R_TYPE64(entry.Info))

				relTable[i/16] = entry
			}

			relTables[section.Name] = relTable
		}
	}

	for _, program := range programs {
		program.Licence = license

		relocTable, found := relTables[".rel"+program.Name.String()]
		if !found {
			continue
		}

		// The offset where main program instructions end and .text instructions start.
		// A value of -1 indicates that the .text section has not yet been added to the program.
		txtInsOff := -1

		// Handle relocation entries for each table. Relocation entries incluede:
		//  - Map references(need to be resolved at load time)
		//  - BPF to BPF function calls (can be resolved here)
		for _, relocEntry := range relocTable {
			refSection := elfFile.Sections[int(relocEntry.Symbol.Section)]

			// If the relocation is to the .text section it is a bpf to bpf call
			if refSection.Name == ".text" {

				if txtInsOff == -1 {
					data, err := refSection.Data()
					if err != nil {
						return nil, fmt.Errorf("unable to get data of section '%s': %w", relocEntry.Symbol.Section, err)
					}

					if len(data)%ebpf.BPFInstSize != 0 {
						return nil, fmt.Errorf("elf .text section is incorrect size for BPF program, should be divisible by 8")
					}

					newInst := make([]ebpf.RawInstruction, len(program.Instructions)+len(data)/ebpf.BPFInstSize)
					txtInsOff = copy(newInst, program.Instructions)
					for i := 0; i < len(data); i += ebpf.BPFInstSize {
						newInst[txtInsOff+i/ebpf.BPFInstSize] = ebpf.RawInstruction{
							Op:  data[i],
							Reg: data[i+1],
							Off: int16(elfFile.ByteOrder.Uint16(data[i+2 : i+4])),
							Imm: int32(elfFile.ByteOrder.Uint32(data[i+4 : i+8])),
						}
					}

					program.Instructions = newInst
				}

				absOff, err := relocEntry.AbsoluteOffset()
				if err != nil {
					return nil, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
				}

				// Update the imm of the call instruction which points to a relocated function
				// in the .text section to reflect the current relative offset
				callInst := &program.Instructions[int(absOff)/ebpf.BPFInstSize]
				callInst.Imm = (int32(txtInsOff) + callInst.Imm) - (int32(absOff) / int32(ebpf.BPFInstSize))

				continue
			}

			// If refered section does not have the EXECINSTR flag, assume it is a map reference

			// The map name is the name of the symbol truncated to BPF_OBJ_NAME_LEN
			mapName := relocEntry.Symbol.Name
			if settings.TruncateNames && len(mapName) > bpftypes.BPF_OBJ_NAME_LEN-1 {
				mapName = mapName[:bpftypes.BPF_OBJ_NAME_LEN-1]
			}

			bpfMap, found := bpfMaps[mapName]
			if !found {
				return nil, fmt.Errorf("program references undefined map named '%s'", mapName)
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
				return nil, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
			}
			relLocations = append(relLocations, absOff)

			program.MapFDLocations[mapName] = relLocations
		}
	}

	return programs, nil
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

	return 0, fmt.Errorf("reloc type not implemented: '%s'", e.Type)
}
