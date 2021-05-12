package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	_ "net/http/pprof"
)

var (
	ifname     = flag.String("ifname", "", "name of the network interface to bind to")
	ip         = flag.String("ip", "", "the ipv4 ip we will use as ping target")
	concurrent = flag.Bool("concurrent", false, "enable concurrent reading and processing of packets")
)

func main() {
	flag.Parse()

	if ifname == nil || *ifname == "" {
		fmt.Fprint(os.Stderr, "flag 'ifname' is required\n")
		os.Exit(1)
	}

	if ip == nil || *ip == "" {
		fmt.Fprint(os.Stderr, "flag 'ip' is required\n")
		os.Exit(1)
	}

	linkip := net.ParseIP(*ip).To4()
	if linkip.Equal(net.IPv4zero) {
		fmt.Fprint(os.Stderr, "flag 'ip' contains an invalid IPv4\n")
		os.Exit(1)
	}

	linkName := *ifname
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get link by name: %s\n", err.Error())
		os.Exit(1)
	}
	linkMAC := link.Attrs().HardwareAddr

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
		Licence: "GPL",
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

	// Add all sockets to the xskmap, index by the queue number.
	for i := 0; i < queues; i++ {
		err = xskmap.Set(i, sockets[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "error while setting xsksock in map: %s\n", err.Error())
			os.Exit(1)
		}
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

	if *concurrent {
		wg := &sync.WaitGroup{}
		done := make(chan struct{})

		// In concurrent mode we just create a routine for every queue we have. This offers beter performance over
		// the MultiWriter because on a multi core processor multiple frames can be handled at the same time.
		// It also requires more setup and manual TX balancing.
		//
		// The 'ethtool' utility can be used to configure NIC's to stear traffic to specific RX queues based on
		// rules. Even tho we have an XDP program which uses a map to select a XSK, the kernel will not allow
		// the XDP program to pick a socket which is not bound to that specific queue. The NIC/driver is leading.
		for i := 0; i < queues; i++ {
			fmt.Println("scheduled listener for queue ", i)

			wg.Add(1)
			go func(queue int, wg *sync.WaitGroup) {
				defer wg.Done()

				for {
					select {
					case <-sigChan:
						close(done)
						return
					case <-done:
						return
					default:
						sock := sockets[queue]
						lease, err := sock.ReadLease()
						if err != nil {
							fmt.Fprintf(os.Stderr, "read lease: %s", err.Error())
						}

						if lease == nil {
							continue
						}

						// Seperator to distinguish between frames
						fmt.Println("------")
						fmt.Printf("received frame on queue: %d\n", queue)

						err = HandleFrame(lease, linkMAC, linkip)
						if err != nil {
							fmt.Fprintf(os.Stderr, "echo reply: %s", err.Error())
						}
					}
				}
			}(i, wg)
		}

		// Wait for all routines to stop before exiting the program
		wg.Wait()
	} else {
		// If we will not be using multiple goroutines, we need to bundle the socket for every queue into one
		// using a multi socket. A multi socket has the same functions available but balances between all
		// sockets.

		multiSock, err := gobpfld.NewXSKMultiSocket(sockets...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "new xsk multi socket: %s\n", err.Error())
		} else {
			// We have to do this for the multi sock since it's timeout overrules that of any
			// underlaying socket.
			// Read the comments at xsksock.Set{Read|Write}Timeout for an explination of the values.
			multiSock.SetReadTimeout(100)
			multiSock.SetWriteTimeout(-1)

			done := false
			for !done {
				select {
				case <-sigChan:
					done = true

				default:
					// Seperator to distinguish between frames
					fmt.Println("------")
					lease, err := multiSock.ReadLease()
					if err != nil {
						fmt.Fprintf(os.Stderr, "read lease: %s\n", err.Error())
						continue
					}

					if lease == nil {
						continue
					}

					err = HandleFrame(lease, linkMAC, linkip)
					if err != nil {
						fmt.Fprintf(os.Stderr, "echo reply: %s", err.Error())
					}
				}
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

func HandleFrame(lease *gobpfld.XSKLease, linkMac net.HardwareAddr, linkIP net.IP) error {
	var err error

	// Swap the MAC addresses
	fmt.Printf("Src MAC: %X, Dst MAC: %X, EthType: %X\n", lease.Data[0:6], lease.Data[6:12], lease.Data[12:14])
	swapMac := make([]byte, 6)
	copy(swapMac, lease.Data[0:6])
	copy(lease.Data[0:6], lease.Data[6:12])
	copy(lease.Data[6:12], swapMac)

	// If EtherType == 0x0806(ARP)
	if lease.Data[12] == 0x08 && lease.Data[13] == 0x06 {
		return HandleARP(lease, linkMac, linkIP)
	}

	// If EtherType == 0x0800(IPv4)
	if lease.Data[12] == 0x08 && lease.Data[13] == 0x00 {
		return EchoReply(lease, linkIP)
	}

	err = lease.Release()
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}

// Since we have no network stack we also need to respond to ARP messages
func HandleARP(lease *gobpfld.XSKLease, linkMac net.HardwareAddr, linkIP net.IP) error {
	// 14-20 left unchanged

	// Change opcode from request to reply
	lease.Data[21] = 2

	// Copy the MAC of our link into the ethernet SRC
	copy(lease.Data[6:12], linkMac)
	// Copy the MAC of our link into the ARP target (will be swapped to source)
	copy(lease.Data[32:38], linkMac)

	// Ignore ARP requests whic hare not for us, otherwise we are ARP spoofing
	if !net.IP(lease.Data[38:42]).Equal(linkIP) {
		err := lease.Release()
		if err != nil {
			return fmt.Errorf("release lease: %w", err)
		}
		return nil
	}

	fmt.Println("respond to arp")

	// Swap sender and target fields
	swap := make([]byte, 10)
	copy(swap, lease.Data[22:32])
	copy(lease.Data[22:32], lease.Data[32:42])
	copy(lease.Data[32:42], swap)

	err := lease.Write()
	if err != nil {
		return fmt.Errorf("release lease: %w", err)
	}
	return nil
}

func EchoReply(lease *gobpfld.XSKLease, linkIP net.IP) error {
	var err error

	// Ignore IP traffic that is not for us
	if !net.IP(lease.Data[30:34]).Equal(linkIP) {
		err = lease.Release()
		if err != nil {
			return fmt.Errorf("release lease: %w", err)
		}
		return nil
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
			return fmt.Errorf("release lease: %w", err)
		}
		return nil
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
		return fmt.Errorf("write lease: %w", err)
	}
	return nil
}
