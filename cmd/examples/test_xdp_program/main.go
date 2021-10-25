package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

// To demonstrate the testing feature, a small program is used that blocks all IPv6 traffic.

func main() {
	program := &gobpfld.ProgramXDP{
		AbstractBPFProgram: gobpfld.AbstractBPFProgram{
			Name:        gobpfld.MustNewObjName("block_ipv6"),
			ProgramType: bpftypes.BPF_PROG_TYPE_XDP,
			License:     "GPL",
		},
	}

	asm := `
		r0 = 2 						# 2 = XDP_PASS
		r2 = *(u32 *)(r1 + 4) 		# r2 = xdp_md.data_end
		r1 = *(u32 *)(r1 + 0)		# r1 = xdp_md.data
		r1 += 12					# EthType is at offset 12
		r3 = r1						# Use r3 for bounds checking
		r3 += 2						# Add 2 since we want to read 2 bytes (u16)
		if r3 > r2 goto return  	# If there are less than 14 bytes, pass the packet (bounds check)
		r1 = *(u16 *)(r1 + 0)   	# Read EthType from frame
		if r1 != 0xDD86 goto return	# If 86DD = IPv6, reversed due to network byte order
		r0 = 1						# 1 = XDP_DROP
	return:
		exit
	`

	inst, err := ebpf.AssemblyToInstructions("inline-asm", strings.NewReader(asm))
	if err != nil {
		panic(err)
	}

	program.Instructions = ebpf.MustEncode(inst)

	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	fmt.Printf("BPF Verifier log:\n%s\n", log)

	if err != nil {
		err2 := program.DecodeToReader(os.Stdout)
		if err2 != nil {
			fmt.Fprintf(os.Stderr, "error while decoding program: %s\n", err.Error())
		}
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
		os.Exit(1)
	}

	ret, err := program.XDPTestProgram(gobpfld.TestXDPProgSettings{
		Data: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // SRC MAC
			0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, // DST MAC
			0x86, 0xDD, // EthType = IPv6
			0x00, 0x00,
		},
		Repeat: 1000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while testing program: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "Duration: %d, return value: %d\n", ret.Duration, ret.ReturnValue)

	ret, err = program.XDPTestProgram(gobpfld.TestXDPProgSettings{
		Data: []byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // SRC MAC
			0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, // DST MAC
			0x08, 0x00, // EthType = IPv4
			0x00, 0x00,
		},
		Repeat: 1000,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while testing program: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stdout, "Duration: %d, return value: %d\n", ret.Duration, ret.ReturnValue)
}
