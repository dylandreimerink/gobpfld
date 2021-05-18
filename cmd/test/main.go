package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/vishvananda/netlink"
)

var (
	ifname = flag.String("ifname", "", "name of the network interface to bind to")
)

func main() {
	flag.Parse()

	if ifname == nil || *ifname == "" {
		fmt.Fprint(os.Stderr, "flag 'ifname' is required\n")
		os.Exit(1)
	}

	linkName := *ifname
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get link by name: %s\n", err.Error())
		os.Exit(1)
	}

	queues, err := gobpfld.GetNetDevQueueCount(linkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get link queue count: %s\n", err.Error())
		os.Exit(1)
	}

	sockets := make([]*gobpfld.XSKSocket, queues)

	for i := 0; i < queues; i++ {
		xsksock, err := gobpfld.NewXSKSocket(gobpfld.XSKSettings{
			NetDevIfIndex: link.Attrs().Index,
			QueueID:       i,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "new socket: %s\n", err.Error())
			os.Exit(1)
		}

		// Set the read timeout to 100ms so we can stop the program even if there is nothing to read.
		// Set the write timeout to infinity since waiting for writes almost never happens(for this example),
		// and retry logic is harder to implement.
		// The default behavour is to never block, this allows for busy polling which has lower latency but
		//  higher CPU usage.
		xsksock.SetReadTimeout(100)
		xsksock.SetWriteTimeout(-1)

		sockets[i] = xsksock
	}

	// Generate a program which will bypass all traffic to userspace
	program := &gobpfld.BPFProgram{
		Name:    gobpfld.MustNewObjName("xsk_bypass"),
		License: "GPL",
		Maps: map[string]gobpfld.BPFMap{
			"xskmap": &gobpfld.XSKMap{
				AbstractMap: gobpfld.AbstractMap{
					Name: gobpfld.MustNewObjName("xskmap"),
					Definition: gobpfld.BPFMapDef{
						Type:       bpftypes.BPF_MAP_TYPE_XSKMAP,
						KeySize:    4, // SizeOf(uint32)
						ValueSize:  4, // SizeOf(uint32)
						MaxEntries: uint32(queues),
					},
				},
			},
		},
		MapFDLocations: map[string][]uint64{
			"xskmap": {
				// LoadConstant64bit is the 2nd instruction in this program. So the first byte of the
				// 2nd instruction is the width of a instruction * 1 to skip the first 1 instruction
				uint64(ebpf.BPFInstSize) * 1,
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
		Instructions: ebpf.MustEncode([]ebpf.Instruction{
			// load ((xdp_md) ctx)->rx_queue_index into R2 (used as 2nd parameter)
			/* r2 = *(u32 *)(r1 + 16) */
			&ebpf.LoadMemory{
				Dest:   ebpf.BPF_REG_2,
				Src:    ebpf.BPF_REG_1,
				Size:   ebpf.BPF_W,
				Offset: 16,
			},
			// Set R1(first parameter) to the address of the xskmap.
			// Which will be set during loading
			/* r1 = xskmap[] */
			&ebpf.LoadConstant64bit{
				Dest: ebpf.BPF_REG_1,
			},
			// Move XDP_PASS into R3 (third argument)
			/* r3 = XDP_PASS */
			&ebpf.Mov64{
				Dest: ebpf.BPF_REG_3,
				Val:  ebpf.XDP_PASS,
			},
			/* call bpf_redirect_map */
			&ebpf.CallHelper{
				Function: 51,
			},
			&ebpf.Exit{}, // exit
		}),
	}

	xskmap := program.Maps["xskmap"].(*gobpfld.XSKMap)
	log, err := program.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:      bpftypes.BPF_PROG_TYPE_XDP,
		VerifierLogLevel: bpftypes.BPFLogLevelBasic,
	})

	program.DecodeToReader(os.Stdout)
	fmt.Fprintln(os.Stderr, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while loading program: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("---")

	var sock *gobpfld.XSKSocket
	err = gobpfld.MapIterForEach(xskmap.Iterator(), uint32(0), &sock, func(key, value interface{}) error {
		fmt.Printf("%d = %v\n", *key.(*uint32), sock.Fd())
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while iterating over map: %s\n", err.Error())
		os.Exit(1)
	}

	// Add all sockets to the xskmap, index by the queue number.
	for i := uint32(0); i < uint32(queues); i++ {
		err = xskmap.Set(i, sockets[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting xsksock to map: %s\n", err.Error())
			os.Exit(1)
		}
	}

	fmt.Println("---")

	err = gobpfld.MapIterForEach(xskmap.Iterator(), uint32(0), &sock, func(key, value interface{}) error {
		fmt.Printf("%d = %v @ %p\n", *key.(*uint32), sock.Fd(), sock)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while iterating over map: %s\n", err.Error())
		os.Exit(1)
	}

	for i := uint32(0); i < uint32(queues); i++ {
		err = xskmap.Delete(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while deleting xsksock in map: %s\n", err.Error())
			os.Exit(1)
		}
	}

	fmt.Println("---")

	err = gobpfld.MapIterForEach(xskmap.Iterator(), uint32(0), &sock, func(key, value interface{}) error {
		fmt.Printf("%d = %v @ %p\n", *key.(*uint32), sock.Fd(), sock)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while iterating over map: %s\n", err.Error())
		os.Exit(1)
	}
}
