//go:build bpftests
// +build bpftests

package integration

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

// This example command is a pure go replacement for the userpace program of the Basic03 program from
// xdp-tutorial. https://github.com/xdp-project/xdp-tutorial/tree/master/basic03-map-counter
// This example has no options but does demonstrate program loading from ELF, attaching to a interface, and interacting with a map
func TestIntegrationXDPstats(t *testing.T) {
	elfFileBytes, err := ebpf.ReadFile("ebpf/xdp_stats_test")
	if err != nil {
		t.Fatal(err)
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{})
	if err != nil {
		t.Fatal(err)
	}

	program := elf.Programs["xdp_stats1_func"].(*gobpfld.ProgramXDP)

	// All maps loaded from elf files are BPFGenericMaps
	statsMap := program.Maps["xdp_stats_map"].(*gobpfld.ArrayMap)

	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})
	if err != nil {
		t.Log(log)
		t.Fatal(err)
	}

	err = program.Attach(gobpfld.ProgXDPAttachOpts{
		InterfaceName: "lo",
		Replace:       true,
	})
	if err != nil {
		t.Fatal(err)
	}

	detach := func() {
		err = program.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
			All: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	defer detach()

	udpConn, err := net.Dial("udp", "127.0.0.1:123")
	if err != nil {
		t.Fatal(err)
	}

	// Write some bogus UDP packets to localhost to generate traffic
	ticker := time.Tick(1 * time.Second)
	endTimer := time.NewTimer(5 * time.Second)
	stop := false
	for !stop {
		select {
		case <-ticker:
			udpConn.Write([]byte("Hello World"))

		case <-endTimer.C:
			stop = true
		}
	}

	// The key is 2 since the program puts stats in the XDP_PASS key which has value 2
	// Tho this is specific to the XDP program we are using as an example.
	var value int64
	err = statsMap.Get(2, &value)
	if err != nil {
		t.Fatal(err)
	}

	if value == 0 {
		t.Fatal("Expected at least one packet")
	}
}
