package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"golang.org/x/sys/unix"

	_ "embed"
)

//go:embed percpu.o
var f embed.FS

// This example command demonstrates how to read from and write to a "per cpu" map.
// Per CPU maps values are always arrays with the same number of elements as the CPU count of the host.
// Therefor arrays or slices need to be used to read from them or read to them.

func main() {
	elfFileBytes, err := f.ReadFile("percpu.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	programs, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while reading ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	program := programs["percpumap"]

	// All maps loaded from elf files are BPFGenericMaps
	counterMap := program.Maps["cnt_map"].(*gobpfld.BPFGenericMap)

	log, err := program.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:      bpftypes.BPF_PROG_TYPE_XDP,
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGINT)

	err = program.XDPLinkAttach(gobpfld.BPFProgramXDPLinkAttachSettings{
		InterfaceName: "lo",
		Replace:       true,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while attaching program to loopback device: %s\n", err.Error())
		os.Exit(1)
	}

	// We need to know how many CPU's this machine has to size our value buffers correctly
	// runtime.NumCPU returns the usable number of CPU's for this process.
	// This number can be different from the number available to the kernel if this process
	// has custom CPU affinity / scheduling. To avoid this the /proc/cpuinfo "file" should be
	// parsed which seems the most reliable method for CPU count detection.
	// But this is not (yet) included in gobpfld.
	numCPUs := runtime.NumCPU()

	ticker := time.Tick(1 * time.Second)
	i := 0
	for {
		select {
		case <-ticker:
			// Alternate between using a slice and an array, just for fun
			i += 1
			if i%2 == 0 {
				key := uint32(0)
				valueSlice := make([]uint64, numCPUs)

				err := counterMap.Get(&key, &valueSlice)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error while getting data from per-cpu map: %s\n", err.Error())
					// Close sigchan to trigger a shutdown
					close(sigChan)
					break
				}

				fmt.Println("-----------------")
				for i := 0; i < numCPUs; i++ {
					fmt.Printf("CPU %d: %d packets processed\n", i, valueSlice[i])
				}

				// Every 10 seconds write the current counts to index 1
				if i%10 == 0 {
					key := uint32(1)

					err := counterMap.Set(&key, &valueSlice, bpfsys.BPFMapElemAny)
					if err != nil {
						fmt.Fprintf(os.Stderr, "error while setting data to per-cpu map: %s\n", err.Error())
						// Close sigchan to trigger a shutdown
						close(sigChan)
						break
					}
				}

			} else {
				key := uint32(0)
				// Array must have a static size, so we pick a number of CPUs we will not exceed
				valueArray := [1024]uint64{}

				err := counterMap.Get(&key, &valueArray)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error while getting data from per-cpu map: %s\n", err.Error())
					// Close sigchan to trigger a shutdown
					close(sigChan)
					break
				}

				fmt.Println("-----------------")
				for i := 0; i < numCPUs; i++ {
					fmt.Printf("CPU %d: %d packets processed\n", i, valueArray[i])
				}
			}
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
