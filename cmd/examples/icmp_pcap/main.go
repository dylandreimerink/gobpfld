package main

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"syscall"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

//go:embed src/sockfilter
var f embed.FS

func main() {
	elfFileBytes, err := f.ReadFile("src/sockfilter")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while reading ELF file: %s\n", err.Error())
		os.Exit(1)
	}

	program := elf.Programs["sockfilter_prog"].(*gobpfld.ProgramSocketFilter)

	log, err := program.Load(gobpfld.ProgSKFilterLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
		VerifierLogSize:  1 << 20,
	})
	fmt.Fprint(os.Stdout, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "program load: %s\n", err.Error())
		os.Exit(1)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "syscall socket: %s", err.Error())
		os.Exit(1)
	}

	err = program.Attach(uintptr(fd))
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket attach: %s", err.Error())
		os.Exit(1)
	}

	// Make a 32KB buffer
	buf := make([]byte, 1<<16)
	for {
		len, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "syscall recvfrom: %s", err.Error())
			os.Exit(1)
		}

		fmt.Printf("% X\n", buf[:len])
	}
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
