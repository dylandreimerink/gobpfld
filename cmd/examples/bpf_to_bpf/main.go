package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpfsys"
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

	program := elf.Programs["firewall_prog"].(*gobpfld.ProgramXDP)

	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
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

	// We need to know how many CPU's this machine has to size our value buffers correctly
	// runtime.NumCPU returns the usable number of CPU's for this process.
	// This number can be different from the number available to the kernel if this process
	// has custom CPU affinity / scheduling. To avoid this the /proc/cpuinfo "file" should be
	// parsed which seems the most reliable method for CPU count detection.
	// But this is not (yet) included in gobpfld.
	numCPUs := runtime.NumCPU()

	ipStats := program.Maps["ip_proto_stats"].(*gobpfld.HashMap)
	tcpStats := program.Maps["tcp_stats"].(*gobpfld.HashMap)
	udpStats := program.Maps["udp_stats"].(*gobpfld.HashMap)

	type trafficStats struct {
		packets uint64
		bytes   uint64
	}

	ticker := time.Tick(1 * time.Second)
	for {
		select {
		case <-ticker:
			fmt.Println("-------------------------")
			fmt.Println("IP Proto stats:")

			var protoNum uint8
			stats := make([]trafficStats, numCPUs)

			attr := &bpfsys.BPFAttrMapElem{
				MapFD:         ipStats.Fd,
				Value_NextKey: uintptr(unsafe.Pointer(&protoNum)),
			}

			for {
				err := bpfsys.MapGetNextKey(attr)
				if err != nil {
					syserr, ok := err.(*bpfsys.BPFSyscallError)
					if !ok || syserr.Errno != syscall.ENOENT {
						fmt.Fprintf(os.Stderr, "error while getting next key from ip_proto_stats: %s\n", err.Error())
						close(sigChan)
					}

					//
					break
				}

				attr.Key = attr.Value_NextKey

				err = ipStats.Get(&protoNum, &stats)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error while getting value from ip_proto_stats: %s\n", err.Error())
					close(sigChan)
					break
				}

				var sum trafficStats
				for _, row := range stats {
					sum.bytes += row.bytes
					sum.packets += row.packets
				}

				fmt.Printf(" %d: pkts: %d, bytes: %d\n", protoNum, sum.packets, sum.bytes)
			}

			fmt.Println("TCP Proto stats:")

			var tcpPort uint16
			attr = &bpfsys.BPFAttrMapElem{
				MapFD:         tcpStats.Fd,
				Value_NextKey: uintptr(unsafe.Pointer(&tcpPort)),
			}

			for {
				err := bpfsys.MapGetNextKey(attr)
				if err != nil {
					syserr, ok := err.(*bpfsys.BPFSyscallError)
					if !ok || syserr.Errno != syscall.ENOENT {
						fmt.Fprintf(os.Stderr, "error while getting next key from tcp_stats: %s\n", err.Error())
						close(sigChan)
					}

					//
					break
				}

				attr.Key = attr.Value_NextKey

				err = tcpStats.Get(&tcpPort, &stats)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error while getting value from tcp_stats: %s\n", err.Error())
					close(sigChan)
					break
				}

				var sum trafficStats
				for _, row := range stats {
					sum.bytes += row.bytes
					sum.packets += row.packets
				}

				fmt.Printf(" %d: pkts: %d, bytes: %d\n", tcpPort, sum.packets, sum.bytes)
			}

			fmt.Println("UDP Proto stats:")

			var udpPort uint16
			attr = &bpfsys.BPFAttrMapElem{
				MapFD:         udpStats.Fd,
				Value_NextKey: uintptr(unsafe.Pointer(&udpPort)),
			}

			for {
				err := bpfsys.MapGetNextKey(attr)
				if err != nil {
					syserr, ok := err.(*bpfsys.BPFSyscallError)
					if !ok || syserr.Errno != syscall.ENOENT {
						fmt.Fprintf(os.Stderr, "error while getting next key from udp_stats: %s\n", err.Error())
						close(sigChan)
					}

					//
					break
				}

				attr.Key = attr.Value_NextKey

				err = udpStats.Get(&udpPort, &stats)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error while getting value from udp_stats: %s\n", err.Error())
					close(sigChan)
					break
				}

				var sum trafficStats
				for _, row := range stats {
					sum.bytes += row.bytes
					sum.packets += row.packets
				}

				fmt.Printf(" %d: pkts: %d, bytes: %d\n", udpPort, sum.packets, sum.bytes)
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
