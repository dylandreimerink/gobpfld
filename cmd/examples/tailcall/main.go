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
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"golang.org/x/sys/unix"
)

//go:embed src/xdp
var f embed.FS

func main() {
	elfFileBytes, err := f.ReadFile("src/xdp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while reading ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	tailProgs := []string{"ipv4_prog", "ipv6_prog", "tcp_prog", "udp_prog"}

	entryProgram := elf.Programs["entry_prog"].(*gobpfld.ProgramXDP)

	log, err := entryProgram.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program 'entry': %s\n", err.Error())
		os.Exit(1)
	}

	// Before we attach the entry program to the network device we load all tail programs and set their fd's
	// in the 'tails' map.
	tailMap := elf.Maps["tails"].(*gobpfld.ProgArrayMap)
	for i, progName := range tailProgs {
		tailProg := elf.Programs[progName].(*gobpfld.ProgramXDP)

		log, err := tailProg.Load(gobpfld.ProgXDPLoadOpts{
			VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
		})

		fmt.Printf("BPF Verifier log:\n%s\n", log)

		if err != nil {
			fmt.Fprintf(os.Stderr, "error while loading program '%s': %s\n", progName, err.Error())
			os.Exit(1)
		}

		err = tailMap.Set(int32(i), tailProg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting prog array fd '%s': %s\n", progName, err.Error())
			os.Exit(1)
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGINT)

	err = entryProgram.Attach(gobpfld.ProgXDPAttachOpts{
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

	ipStats := elf.Maps["ip_proto_stats"].(*gobpfld.HashMap)
	tcpStats := elf.Maps["tcp_stats"].(*gobpfld.HashMap)
	udpStats := elf.Maps["udp_stats"].(*gobpfld.HashMap)

	type trafficStats struct {
		packets uint64
		bytes   uint64
	}

	ticker := time.Tick(1 * time.Second)
	for {
		select {
		case <-ticker:
			printStats := func(k, v interface{}) error {
				var sum trafficStats
				for _, row := range *v.(*[]trafficStats) {
					sum.bytes += row.bytes
					sum.packets += row.packets
				}

				var key interface{}
				switch t := k.(type) {
				case *uint8:
					key = *t
				case *uint16:
					key = *t
				}

				fmt.Printf(" %d: pkts: %d, bytes: %d\n", key, sum.packets, sum.bytes)

				return nil
			}

			var (
				protoNum uint8
				portNum  uint16
			)

			stats := make([]trafficStats, numCPUs)

			fmt.Println("-------------------------")
			fmt.Println("IP Proto stats:")
			iter := ipStats.Iterator()

			// gobpfld.MapIterForEach(ipStats.Iterator(), &protoNum, &stats, printStats)
			err := iter.Init(&protoNum, &stats)
			if err != nil {
				fmt.Fprintf(os.Stderr, "init: %s\n", err.Error())
				continue
			}

			var updated bool
			for updated, err = iter.Next(); updated && err == nil; updated, err = iter.Next() {
				err = printStats(&protoNum, &stats)
				if err != nil {
					fmt.Fprintf(os.Stderr, "printStats: %s\n", err.Error())
					continue
				}
			}

			fmt.Println("TCP Proto stats:")
			gobpfld.MapIterForEach(tcpStats.Iterator(), &portNum, &stats, printStats)

			fmt.Println("UDP Proto stats:")
			gobpfld.MapIterForEach(udpStats.Iterator(), &portNum, &stats, printStats)

		case <-sigChan:
			fmt.Println("Detaching XPD program and stopping")

			err = entryProgram.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
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
