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
						Definition: BPFMapDef{
							Type:       bpftypes.BPFMapType(elfFile.ByteOrder.Uint32(data[i : i+4])),
							KeySize:    elfFile.ByteOrder.Uint32(data[i+4 : i+8]),
							ValueSize:  elfFile.ByteOrder.Uint32(data[i+8 : i+12]),
							MaxEntries: elfFile.ByteOrder.Uint32(data[i+12 : i+16]),
							Flags:      elfFile.ByteOrder.Uint32(data[i+16 : i+20]),
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
								err = bpfMap.Name.SetString(section.Name[:bpftypes.BPF_OBJ_NAME_LEN])
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
					err = program.Name.SetString(section.Name[:bpftypes.BPF_OBJ_NAME_LEN])
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

			if section.Name != ".relxdp_stats1" {
				continue
			}

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
				entry.Type = elf.R_AARCH64(elf.R_TYPE64(entry.Info))

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

		// Populate program with map reloc data from reloc table
		for _, relocEntry := range relocTable {
			bpfMap, found := bpfMaps[relocEntry.Symbol.Name]
			if !found {
				return nil, fmt.Errorf("program references undefined map named '%s'", relocEntry.Symbol.Name)
			}

			// Add map to list of maps used by program if not already in list
			_, found = program.Maps[relocEntry.Symbol.Name]
			if !found {
				program.Maps[relocEntry.Symbol.Name] = bpfMap
			}

			relLocations := program.MapFDLocations[relocEntry.Symbol.Name]
			if relLocations == nil {
				relLocations = []uint64{}
			}

			absOff, err := relocEntry.AbsoluteOffset()
			if err != nil {
				return nil, fmt.Errorf("unable to calculate absolute offset for relocation entry: %w", err)
			}
			relLocations = append(relLocations, absOff)

			program.MapFDLocations[relocEntry.Symbol.Name] = relLocations
		}
	}

	return programs, nil
}

type ELFRelocTable []ELFRelocEntry

type ELFRelocEntry struct {
	elf.Rel64

	Symbol *elf.Symbol
	Type   elf.R_AARCH64
}

func (e *ELFRelocEntry) AbsoluteOffset() (uint64, error) {
	switch e.Type {
	case elf.R_AARCH64_P32_ABS32:
		// Just the absolute offset from the begining of the program section
		return e.Off, nil
	}

	return 0, fmt.Errorf("reloc type not implemented: '%s'", e.Type)
}
