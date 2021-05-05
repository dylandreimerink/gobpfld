package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"net"
	"os"

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

	program := elf.Programs["sockfilter"]

	log, err := program.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:      bpftypes.BPF_PROG_TYPE_SOCKET_FILTER,
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
		VerifierLogSize:  1 << 20,
	})
	fmt.Fprint(os.Stdout, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "program load: %s\n", err.Error())
		os.Exit(1)
	}

	lc := net.ListenConfig{
		Control: program.SocketAttachControlFunc,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp", ":3000")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen packet: %s\n", err.Error())
		os.Exit(1)
	}

	// Make a 32KB buffer
	buf := make([]byte, 1<<16)
	for {
		len, _, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "conn read from: %s", err.Error())
			os.Exit(1)
		}

		fmt.Printf("% X\n", buf[:len])
	}
}
