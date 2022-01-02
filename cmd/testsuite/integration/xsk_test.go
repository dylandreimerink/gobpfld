//go:build bpftests
// +build bpftests

package integration

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	ebpfPkg "github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
	"github.com/vishvananda/netlink"
)

var (
	ifname = "lo"
	ip     = "127.0.0.2"

	arpCount int
	ipCount  int
)

func TestIntegrationXSK(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Map.Has(kernelsupport.KFeatMapAFXDP) {
		t.Skip("XSK not supported in by the kernel")
	}

	linkName := ifname
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		t.Fatalf("get link by name: %s\n", err.Error())
	}

	// Create an new XSK socket, bound to queue 0.
	// NOTE this example only works on non-multi queue NIC's
	xsksock, err := gobpfld.NewXSKSocket(gobpfld.XSKSettings{
		NetDevIfIndex: link.Attrs().Index,
		QueueID:       0,
	})
	if err != nil {
		t.Fatalf("new socket: %s\n", err.Error())
	}
	defer func() {
		err = xsksock.Close()
		if err != nil {
			t.Log(err)
			t.Fail()
		}
	}()

	// Block forever until we can read or write (default behavour is to never block)
	xsksock.SetReadTimeout(-1)
	xsksock.SetWriteTimeout(-1)

	// Generate a program which will bypass all traffic to userspace
	program := &gobpfld.ProgramXDP{
		AbstractBPFProgram: gobpfld.AbstractBPFProgram{
			Name:        gobpfld.MustNewObjName("xsk_bypass"),
			ProgramType: bpftypes.BPF_PROG_TYPE_XDP,
			License:     "GPL",
			Maps: map[string]gobpfld.BPFMap{
				"xskmap": &gobpfld.XSKMap{
					AbstractMap: gobpfld.AbstractMap{
						Name: gobpfld.MustNewObjName("xskmap"),
						Definition: gobpfld.BPFMapDef{
							Type:       bpftypes.BPF_MAP_TYPE_XSKMAP,
							KeySize:    4, // SizeOf(uint32)
							ValueSize:  4, // SizeOf(uint32)
							MaxEntries: 5,
						},
					},
				},
			},
			MapFDLocations: map[string][]uint64{
				"xskmap": {
					// LoadConstant64bit is the 2nd instruction in this program. So the first byte of the
					// 2nd instruction is the width of a instruction * 1 to skip the first 1 instruction
					uint64(ebpfPkg.BPFInstSize) * 1,
				},
			},
			// Instructions for this program:
			// int xsk_bypass(struct xdp_md *ctx)
			// {
			// 	return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
			// }
			//
			// NOTE this program only works in linux kernel >= 5.3
			// https://elixir.bootlin.com/linux/v5.12.2/source/tools/lib/bpf/xsk.c#L416
			Instructions: ebpfPkg.MustEncode([]ebpfPkg.Instruction{
				// load ((xdp_md) ctx)->rx_queue_index into R2 (used as 2nd parameter)
				/* r2 = *(u32 *)(r1 + 16) */
				&ebpfPkg.LoadMemory{
					Dest:   ebpfPkg.BPF_REG_2,
					Src:    ebpfPkg.BPF_REG_1,
					Size:   ebpfPkg.BPF_W,
					Offset: 16,
				},
				// Set R1(first parameter) to the address of the xskmap.
				// Which will be set during loading
				/* r1 = xskmap[] */
				&ebpfPkg.LoadConstant64bit{
					Dest: ebpfPkg.BPF_REG_1,
				},
				// Move XDP_PASS into R3 (third argument)
				/* r3 = XDP_PASS */
				&ebpfPkg.Mov64{
					Dest:  ebpfPkg.BPF_REG_3,
					Value: ebpfPkg.XDP_PASS,
				},
				/* call bpf_redirect_map */
				&ebpfPkg.CallHelper{
					Function: 51,
				},
				&ebpfPkg.Exit{}, // exit
			}),
		},
	}

	xskmap := program.Maps["xskmap"].(*gobpfld.XSKMap)
	defer func() {
		err = xskmap.Close()
		if err != nil {
			t.Log(xskmap)
			t.Fail()
		}
	}()

	log, err := program.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	if err != nil {
		var buf strings.Builder
		program.DecodeToReader(&buf)
		t.Log(buf.String())
		t.Log(log)
		t.Fatalf("error while loading program: %s\n", err.Error())
	}

	// Set the xsksocket for queue ID 0
	err = xskmap.Set(0, xsksock)
	if err != nil {
		t.Fatalf("error while setting xsksock in map: %s\n", err.Error())
	}

	err = program.Attach(gobpfld.ProgXDPAttachOpts{
		InterfaceName: linkName,
		Replace:       true,
	})
	if err != nil {
		t.Fatalf("error while attaching program to loopback device: %s\n", err.Error())
	}
	defer func() {
		program.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
			All: true,
		})
	}()

	// Read frames from XSK socket and increment counter
	go func() {
		for {
			lease, err := xsksock.ReadLease()
			if err != nil {
				t.Logf("read lease: %s\n", err.Error())
				t.Fail()
				break
			}

			if lease == nil {
				break
			}

			err = HandleFrame(lease)
			if err != nil {
				t.Logf("handle frame: %s\n", err.Error())
				t.Fail()
			}
		}
	}()

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

	if ipCount == 0 && arpCount == 0 {
		t.Fatal("no frames received")
	}
}

func HandleFrame(lease *gobpfld.XSKLease) error {
	var err error
	defer func() {
		err = lease.Release()
		if err != nil {
			err = fmt.Errorf("release lease: %w", err)
		}
	}()

	// If EtherType == 0x0806(ARP)
	if lease.Data[12] == 0x08 && lease.Data[13] == 0x06 {
		arpCount++
	}

	// If EtherType == 0x0800(IPv4)
	if lease.Data[12] == 0x08 && lease.Data[13] == 0x00 {
		ipCount++
	}

	return err
}
