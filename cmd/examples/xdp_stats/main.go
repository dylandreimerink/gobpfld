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
	"golang.org/x/sys/unix"

	_ "embed"
)

//go:embed bpf/basic03_map_counter
var f embed.FS

// This example command is a pure go replacement for the userpace program of the Basic03 program from
// xdp-tutorial. https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter
// This example has no options but does demonstrate program loading from ELF, attaching to a interface, and interacting with a map

func main() {
	elfFileBytes, err := f.ReadFile("bpf/basic03_map_counter")
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

	// All maps loaded from elf files are BPFGenericMaps
	statsMap := program.Maps["xdp_stats_map"].(*gobpfld.ArrayMap)

	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
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
			err = statsMap.Get(2, &value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error while getting stats from map: %s\n", err.Error())
				detach()
				os.Exit(1)
			}

			fmt.Printf("%d packets were processed\n", value)

		case <-sigChan:
			fmt.Println("Detaching XPD program and stopping")

			detach()

			os.Exit(0)
		}
	}
}
