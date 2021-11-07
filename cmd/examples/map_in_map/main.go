package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"golang.org/x/sys/unix"

	_ "embed"
)

//go:embed bpf/map_in_map_counter
var f embed.FS

func main() {
	elfFileBytes, err := f.ReadFile("bpf/map_in_map_counter")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while reading ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	program := elf.Programs["xdp_stats1_func"].(*gobpfld.ProgramXDP)

	innerDef := gobpfld.BPFMapDef{
		Type:       bpftypes.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 5,
		Flags:      bpftypes.BPFMapFlagsInnerMap,
	}

	firstStatsMap := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name:       gobpfld.MustNewObjName("even_proto"),
			Definition: innerDef,
		},
	}

	secondStatsMap := &gobpfld.ArrayMap{
		AbstractMap: gobpfld.AbstractMap{
			Name:       gobpfld.MustNewObjName("uneven_proto"),
			Definition: innerDef,
		},
	}

	mapInMap := program.Maps["map_of_maps"].(*gobpfld.ArrayOfMapsMap)

	// We need to set the inner map definition, All
	mapInMap.InnerMapDef = innerDef

	// Load the program, this will also load the maps
	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
		os.Exit(1)
	}

	err = firstStatsMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading even stats map: %s\n", err.Error())
		os.Exit(1)
	}

	err = mapInMap.Set(0, firstStatsMap, bpfsys.BPFMapElemAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while setting value map in map: %s\n", err.Error())
		os.Exit(1)
	}

	err = secondStatsMap.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading uneven stats map: %s\n", err.Error())
		os.Exit(1)
	}

	err = mapInMap.Set(1, secondStatsMap, bpfsys.BPFMapElemAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while setting value map in map: %s\n", err.Error())
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGINT)

	err = program.Attach(gobpfld.ProgXDPAttachOpts{
		InterfaceName: "lo",
		Replace:       true,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while attaching program to loopback device: %s\n", err.Error())
		os.Exit(1)
	}

	detach := func() {
		err = program.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
			All: true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while detaching program: %s\n", err.Error())
			os.Exit(1)
		}
	}

	ticker := time.Tick(1 * time.Second)
	for {
		select {
		case <-ticker:
			// The key is 2 since the program puts stats in the XDP_PASS key which has value 2
			// Tho this is specific to the XDP program we are using as an example.
			var value int64
			err = firstStatsMap.Get(2, &value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting stats from first map: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			fmt.Printf("first map has %d packets were processed\n", value)

			err = secondStatsMap.Get(2, &value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting stats from second map: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			fmt.Printf("second map has %d packets were processed\n", value)

			fmt.Println("Swapping maps")

			zeroMap, err := mapInMap.Get(0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting map at index 0: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			fmt.Println("Index 0 fd: ", zeroMap.GetFD())

			oneMap, err := mapInMap.Get(1)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting map at index 1: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			fmt.Println("Index 1 fd: ", oneMap.GetFD())

			err = mapInMap.Set(0, oneMap, bpfsys.BPFMapElemAny)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while setting map at index 0: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			err = mapInMap.Set(1, zeroMap, bpfsys.BPFMapElemAny)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while setting map at index 1: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

		case <-sigChan:
			fmt.Println("Detaching XPD program and stopping")

			detach()

			os.Exit(0)
		}
	}
}
