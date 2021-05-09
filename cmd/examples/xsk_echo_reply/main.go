package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	_ "net/http/pprof"
)

var ifname = flag.String("ifname", "eth0", "name of the network interface to bind to")

func main() {
	flag.Parse()

	linkName := *ifname
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get link by name: %s\n", err.Error())
		os.Exit(1)
	}

	// Create an new XSK socket, bound to queue 0.
	// NOTE this example only works on non-multi queue NIC's
	xsksock, err := gobpfld.NewXSKSocket(gobpfld.XSKSettings{
		NetDevIfIndex: link.Attrs().Index,
		QueueID:       0,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "new socket: %s\n", err.Error())
		os.Exit(1)
	}

	// Block forever until we can read or write (default behavour is to never block)
	xsksock.SetReadTimeout(-1)
	xsksock.SetWriteTimeout(-1)

	// Generate a program which will bypass all traffic to userspace
	program := &gobpfld.BPFProgram{
		Name:    gobpfld.MustNewObjName("xsk_bypass"),
		Licence: "GPL",
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

	// Set the xsksocket for queue ID 0
	err = xskmap.Set(0, xsksock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while setting xsksock in map: %s\n", err.Error())
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, unix.SIGTERM, unix.SIGINT)

	err = program.XDPLinkAttach(gobpfld.BPFProgramXDPLinkAttachSettings{
		InterfaceName: linkName,
		Replace:       true,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "error while attaching program to loopback device: %s\n", err.Error())
		os.Exit(1)
	}

	done := false
	for !done {
		select {
		case <-sigChan:
			done = true

		default:
			// Seperator to distinguish between frames
			fmt.Println("------")
			lease, err := xsksock.ReadLease()
			if err != nil {
				fmt.Fprintf(os.Stderr, "read lease: %s\n", err.Error())
				break
			}

			if lease == nil {
				break
			}

			// Swap the MAC addresses
			fmt.Printf("Src MAC: %X, Dst MAC: %X, EthType: %X\n", lease.Data[0:6], lease.Data[6:12], lease.Data[12:14])
			swapMac := make([]byte, 6)
			copy(swapMac, lease.Data[0:6])
			copy(lease.Data[0:6], lease.Data[6:12])
			copy(lease.Data[6:12], swapMac)

			// If EtherType != 0x0800(IPv4)
			if !(lease.Data[12] == 0x08 && lease.Data[13] == 0x00) {
				err = lease.Release()
				if err != nil {
					fmt.Fprintf(os.Stderr, "release lease: %s\n", err.Error())
					break
				}
				continue
			}

			fmt.Printf("IPv4 Src: %X, Dst: %X, Proto: %X\n", lease.Data[26:30], lease.Data[30:34], lease.Data[23])
			swapIP := make([]byte, 4)
			copy(swapIP, lease.Data[26:30])
			copy(lease.Data[26:30], lease.Data[30:34])
			copy(lease.Data[30:34], swapIP)

			fmt.Printf("IPv4 Checksum in: %X\n", lease.Data[24:26])

			// Zero the checksum
			lease.Data[24] = 0x00
			lease.Data[25] = 0x00

			// Calculate header checksum
			// https://en.wikipedia.org/wiki/IPv4_header_checksum
			var sum uint32
			for i := 14; i < 34; i += 2 {
				sum += uint32(lease.Data[i]) << 8
				sum += uint32(lease.Data[i+1])
			}
			for {
				// Break when sum is less or equals to 0xFFFF
				if sum <= 65535 {
					break
				}
				// Add carry to the sum
				sum = (sum >> 16) + uint32(uint16(sum))
			}
			checkSum := ^uint16(sum)
			lease.Data[24] = byte(checkSum >> 8)
			lease.Data[25] = byte(checkSum & 0xFF)

			fmt.Printf("IPv4 Checksum out: %X\n", lease.Data[24:26])

			// If Protocol != 0x01(ICMPv4)
			if lease.Data[23] != 0x01 {
				err = lease.Release()
				if err != nil {
					fmt.Fprintf(os.Stderr, "release lease: %s\n", err.Error())
					break
				}
				continue
			}

			fmt.Printf("ICMPv4 Type: %X, Code: %X\n", lease.Data[34], lease.Data[35])
			// Set type to 0 to get 0,0 = Echo Reply
			lease.Data[34] = 0

			fmt.Printf("ICMPv4 Checksum in: %X\n", lease.Data[36:38])

			// clear icmp checksum
			lease.Data[36] = 0x00
			lease.Data[37] = 0x00

			// Calculate ICMP checksum
			sum = 0
			for i := 34; i < len(lease.Data); i += 2 {
				sum += uint32(lease.Data[i]) << 8
				sum += uint32(lease.Data[i+1])
			}
			for {
				// Break when sum is less or equals to 0xFFFF
				if sum <= 65535 {
					break
				}
				// Add carry to the sum
				sum = (sum >> 16) + uint32(uint16(sum))
			}
			checkSum = ^uint16(sum)
			lease.Data[36] = byte(checkSum >> 8)
			lease.Data[37] = byte(checkSum & 0xFF)

			fmt.Printf("ICMPv4 Checksum out: %X\n", lease.Data[36:38])

			// Now that we have converted the request into a reply in the same memory buffer
			// we can just write this buffer back to the network interface
			err = lease.Write()
			if err != nil {
				fmt.Fprintf(os.Stderr, "write back: %s\n", err.Error())
			}
		}
	}

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
