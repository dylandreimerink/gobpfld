package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"

	_ "embed"
)

//go:embed basic03_map_counter.o
var f embed.FS

// This example command is a pure go replacement for the userpace program of the Basic03 program from
// xdp-tutorial. https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter
// This example has no options but does demonstrate program loading from ELF, attaching to a interface, and interacting with a map

func main() {
	elfFileBytes, err := f.ReadFile("basic03_map_counter.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	programs, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while reading ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	program := programs["xdp_stats1"]

	// All maps loaded from elf files are BPFGenericMaps
	statsMap := program.Maps["xdp_stats_map"].(*gobpfld.BPFGenericMap)

	log, err := program.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:        bpftypes.BPF_PROG_TYPE_XDP,
		VerifierLogLevel:   bpftypes.BPFLogLevelBasic,
		ExpectedAttachType: bpftypes.BPF_CGROUP_INET_INGRESS,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	err = program.XDPLinkAttach(gobpfld.BPFProgramXDPLinkAttachSettings{
		InterfaceName: "lo",
		Replace:       true,
		XDPMode:       gobpfld.XDPModeSKB,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while attaching program to loopback device: %s\n", err.Error())
		os.Exit(1)
	}

	ticker := time.Tick(1 * time.Second)
	for {
		select {
		case <-ticker:
			// The key is 2 since the program puts stats in the XDP_PASS key which has value 2
			// Tho this is specific to the XDP program we are using as an example.
			key := uint32(2)
			var value int64

			err = statsMap.Get(&key, &value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting stats from map: %s\n", err.Error())
				os.Exit(1)
			}

			fmt.Printf("%d packets were processed\n", value)

		case <-sigChan:
			fmt.Println("Detaching XPD program and stopping")

			err = program.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
				All: true,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while detaching program: %s\n", err.Error())
				os.Exit(1)
			}

			os.Exit(0)
		}
	}
}
