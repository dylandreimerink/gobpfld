package gobpfld

import (
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"
	"unsafe"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
	"golang.org/x/sys/unix"
)

var (
	_ io.Reader = (*XSKSocket)(nil)
	_ io.Writer = (*XSKSocket)(nil)
	_ io.Closer = (*XSKSocket)(nil)
)

// TODO add support for multiple queues

type XSKSocket struct {
	fd int

	// memory region where frames are exchanged with kernel
	umem     []byte
	settings XSKSettings

	// Buffered channel containing addresses frames which can be used
	// for transmission
	txAddrs          chan uint64
	completionTicker *time.Ticker

	rx         xskDescRing
	tx         xskDescRing
	fill       xskAddrRing
	completion xskAddrRing

	readTimeout int
	// poll timeout while writing in miliseconds, if -1 we will never block(skip poll)
	// if 0, no timeout block-forever. >0 block for x ms if no data can be writen
	writeTimeout int
}

// Fd returns the file descriptor of the socket.
func (xs *XSKSocket) Fd() int {
	return xs.fd
}

// SetWriteTimeout sets the timeout for Write and XSKLease.WriteBack calls.
// If ms == 0 (default), we will never block/wait and error if we can't write at once.
// If ms == -1, we will block forever until we can write.
// If ms > 0, we will wait for x miliseconds for an oppurunity to write or error afterwards.
func (xs *XSKSocket) SetWriteTimeout(ms int) error {
	if ms < -1 {
		return fmt.Errorf("timeout must be -1, 0, or positive amount of miliseconds")
	}

	xs.writeTimeout = ms

	return nil
}

// SetReadTimeout sets the timeout for Read and ReadLease calls.
// If ms == 0 (default), we will never block/wait and return no data if there isn't any ready.
// If ms == -1, we will block forever until we can read.
// If ms > 0, we will wait for x miliseconds for an oppurunity to read or return no data.
func (xs *XSKSocket) SetReadTimeout(ms int) error {
	if ms < -1 {
		return fmt.Errorf("timeout must be -1, 0, or positive amount of miliseconds")
	}

	xs.readTimeout = ms

	return nil
}

// If the need wakeup flag is set on the ring the kernel requests that we
// wakeup the fill ring with a poll syscall
// https://patchwork.ozlabs.org/project/netdev/patch/1560411450-29121-3-git-send-email-magnus.karlsson@intel.com/
func (xs *XSKSocket) wakeupFill() error {
	if *(*uint32)(xs.fill.flags)&unix.XDP_RING_NEED_WAKEUP == 1 {
		_, err := unix.Poll([]unix.PollFd{{Fd: int32(xs.fd), Events: unix.POLLOUT}}, 0)
		if err != nil {
			return fmt.Errorf("poll fill: %w", err)
		}
	}

	return nil
}

// If the need wakeup flag is set on the ring the kernel requests that we
// wakeup the fill ring with a poll syscall
// https://patchwork.ozlabs.org/project/netdev/patch/1560411450-29121-3-git-send-email-magnus.karlsson@intel.com/
func (xs *XSKSocket) wakeupTx() error {
	if *(*uint32)(xs.tx.flags)&unix.XDP_RING_NEED_WAKEUP == 1 {
		err := bpfsys.Sendto(xs.fd, nil, syscall.MSG_DONTWAIT, unsafe.Pointer(&bpfsys.Zero), bpfsys.Socklen(0))
		if err != nil {
			if sysErr, ok := err.(*bpfsys.BPFSyscallError); ok {
				switch sysErr.Errno {
				// These errors occur regulairly when load is high, ignore these errors, the next time
				// wakeupTx is called it will trigger the kernel to read the full ring anyway.
				// https://github.com/torvalds/linux/blob/b741596468b010af2846b75f5e75a842ce344a6e/samples/bpf/xdpsock_user.c#L1095
				case syscall.EBUSY,
					syscall.EAGAIN,
					syscall.ENOBUFS,
					syscall.ENETDOWN:
					return nil
				}
			}

			return fmt.Errorf("syscall sendto: %w", err)
		}
	}

	return nil
}

func (xs *XSKSocket) dequeueRx() (*descriptor, error) {
	desc := xs.rx.Dequeue()
	// there is nothing to dequeue
	if desc == nil {
		// Return at once if blocking is disabled
		if xs.readTimeout == 0 {
			return nil, nil
		}

		n, err := unix.Poll([]unix.PollFd{{Fd: int32(xs.fd), Events: unix.POLLIN}}, xs.readTimeout)
		if err != nil {
			return nil, fmt.Errorf("poll: %w", err)
		}

		// If n == 0, the timeout was reached
		if n == 0 {
			return nil, nil
		}

		desc = xs.rx.Dequeue()
		if desc == nil {
			return desc, fmt.Errorf("no desc after poll")
		}
	}

	return desc, nil
}

// Read implements io.Reader, however we have to implement this with a memory copy which is not ideal
// for efficiency. For zero copy packet access ReadLease should be used.
func (xs *XSKSocket) Read(p []byte) (n int, err error) {
	desc, err := xs.dequeueRx()
	if err != nil {
		return 0, fmt.Errorf("dequeue rx: %w", err)
	}
	if desc == nil {
		return 0, nil
	}

	// unlike the ReadLease function, we ignore headspace since any benefit is lost
	// during the copy.
	len := copy(p, xs.umem[desc.addr:desc.addr+uint64(desc.len)])

	err = xs.fill.Enqueue(addrToFrameStart(desc.addr, xs.settings.FrameSize))
	if err != nil {
		return len, fmt.Errorf("fill enqueue: %w", err)
	}

	err = xs.wakeupFill()
	if err != nil {
		return len, err
	}

	return len, nil
}

// XSKLease is used to "lease" a piece of buffer memory from the socket and return it after the user
// is done using it. This allows us to implement true zero copy packet access.
// After a XSKLease is released or written the underlaying array of Data will be repurposed, to avoid strage bugs
// users must use Data or sub-slices of Data after the lease has been released.
type XSKLease struct {
	Data []byte
	// The amount of bytes which are prefixed at the start which don't contain frame data.
	// This headroom can be used to add an extra header(encapsulation) without having to
	// copy or move the existing packet data.
	Headroom int
	// dataAddr is the memory address at the start of the headroom.
	dataAddr uint64
	sock     *XSKSocket
	// If true the frame address originates from the txAddrs chan
	fromTx bool
}

// Release releases the leased memory so the kernel can fill it with new data.
func (xl *XSKLease) Release() error {
	// Remove reference to Data since it is invalid from now
	xl.Data = nil

	frameAddr := addrToFrameStart(xl.dataAddr, xl.sock.settings.FrameSize)

	// If the this is a tx lease, we can just return the unused address to the txAddrs buffer
	if xl.fromTx {
		xl.sock.txAddrs <- frameAddr
	} else {
		// else, this lease was a rx lease in which case it must be returned to the fill ring

		// Enqueue the address of the frame on the fill queue so it can be reused
		err := xl.sock.fill.Enqueue(frameAddr)
		if err != nil {
			return fmt.Errorf("enqueue fill: %w", err)
		}

		err = xl.sock.wakeupFill()
		if err != nil {
			return err
		}
	}

	return nil
}

// Write writes a lease to the network interface. The len property of the 'Data' slice - 'Headroom' is the length of
// the packet. Make sure to resize the Data to the size of the data to be transmitted.
// The headroom should always be included(never resize the start of the slice). The 'Headroom' should be used
// to indicate from which byte the headroom starts.
// After Write has been called the lease will be released and the Data slice or its subslices should not
// be used anymore.
func (xl *XSKLease) Write() error {
	if len(xl.Data) > xl.sock.settings.FrameSize {
		return fmt.Errorf("lease has been expanded beyond framesize, can't transmit")
	}

	err := xl.sock.enqueueTx(descriptor{
		// When enqueueing, we don't want to send the headroom bytes
		addr: xl.dataAddr + uint64(xl.Headroom),
		// Data should contain headroom + packet, since we will not be sending headroom
		// we need to subtract the amout of headroom from the length of Data to get the correct packet length
		len: uint32(len(xl.Data) - xl.Headroom),
	})
	if err != nil {
		return fmt.Errorf("tx enqueue: %w", err)
	}

	err = xl.sock.wakeupTx()
	if err != nil {
		return err
	}

	// If the lease was from the fill->rx lifecycle
	if !xl.fromTx {
		// Since a frame from the fill->rx lifecycle was used to transmit, we will now get a frame from
		// the tx->completion lifecycle and insert it into the fill ring so we end up with the same
		// amount of frames available for both cycles. If we don't do this the fill->rx cycle will run
		// out of frames.
		// The completion queue is full at rest at max capacity, so first dequeue one frame to make
		// room for the frame we are about to enqueue in tx, just in case the kernel can transmit
		// faster than we can dequeue.
		addr := <-xl.sock.txAddrs

		err := xl.sock.fill.Enqueue(addr)
		if err != nil {
			return fmt.Errorf("fill enqueue: %w", err)
		}

		err = xl.sock.wakeupFill()
		if err != nil {
			return err
		}
	}

	// Set data to nil to indicate that it is no longer valid to use
	xl.Data = nil

	return nil
}

// WriteLease creates a XSKLease which points to a piece of preallocated memory. This memory can be used to
// build packets for writing. Unlike XSKLeases gotten from ReadLease, write leases have no Headroom.
// The Data slice of the lease is the full length of the usable frame, this length should not be exceeded.
// Any memory held by the lease can't be reused until released or written.
//
// This function blocks until a frame for transmission is available and is not subject to the write timeout.
func (xs *XSKSocket) WriteLease() (lease *XSKLease, err error) {
	addr := <-xs.txAddrs
	return &XSKLease{
		Headroom: 0,
		Data:     xs.umem[addr : addr+uint64(xs.settings.FrameSize)],
		dataAddr: addr,
		sock:     xs,
		fromTx:   true,
	}, nil
}

// ReadLease reads a frame from the socket and returns its memory in a XSKLease. After reading the contents of the
// frame it can be released or written, both will allow the memory to be reused. Calling Write on the lease will
// cause the contents of Data to be written back to the network interface. The contents of Data can be modified
// before calling Write thus allowing a program to implement zero-copy/zero-allocation encaptulation or
// request/response protocols.
func (xs *XSKSocket) ReadLease() (lease *XSKLease, err error) {
	desc, err := xs.dequeueRx()
	if err != nil {
		return nil, fmt.Errorf("dequeue rx: %w", err)
	}
	if desc == nil {
		return nil, nil
	}

	return &XSKLease{
		Headroom: xs.settings.Headroom,
		Data:     xs.umem[desc.addr-uint64(xs.settings.Headroom) : desc.addr+uint64(desc.len)],
		dataAddr: desc.addr,
		sock:     xs,
	}, nil
}

func (xs *XSKSocket) enqueueTx(desc descriptor) error {
	err := xs.tx.Enqueue(desc)
	if err != nil {
		if err != errBufferFull {
			// Put the frame address back in the chan so we don't lose it
			xs.txAddrs <- desc.addr

			return fmt.Errorf("tx enqueue: %w", err)
		}

		_, err := unix.Poll([]unix.PollFd{{Fd: int32(xs.fd), Events: unix.POLLOUT}}, xs.writeTimeout)
		if err != nil {
			return fmt.Errorf("poll: %w", err)
		}

		err = xs.tx.Enqueue(desc)
		if err != nil {
			// Put the frame address back in the chan so we don't lose it
			xs.txAddrs <- desc.addr

			return fmt.Errorf("tx enqueue: %w", err)
		}
	}

	return nil
}

// Write implements io.Writer. The interface requires us to copy p into umem which is not
// optimal for speed. For maximum performance use WriteLease instead.
func (xs *XSKSocket) Write(p []byte) (n int, err error) {
	if len(p) > xs.settings.FrameSize {
		return 0, fmt.Errorf("data is larget than frame size of %d", xs.settings.FrameSize)
	}

	// We assume we will never be blocking here for long
	addr := <-xs.txAddrs

	len := copy(xs.umem[addr:addr+uint64(len(p))], p)

	err = xs.enqueueTx(descriptor{
		addr: addr,
		len:  uint32(len),
	})
	if err != nil {
		return 0, err
	}

	err = xs.wakeupTx()
	if err != nil {
		return 0, err
	}

	return len, nil
}

func (xs *XSKSocket) Close() error {
	err := xs.rx.Close()
	if err != nil {
		return fmt.Errorf("rx close: %w", err)
	}

	err = xs.tx.Close()
	if err != nil {
		return fmt.Errorf("tx close: %w", err)
	}

	err = xs.fill.Close()
	if err != nil {
		return fmt.Errorf("fill close: %w", err)
	}

	if xs.completionTicker != nil {
		xs.completionTicker.Stop()
	}

	err = xs.completion.Close()
	if err != nil {
		return fmt.Errorf("completion close: %w", err)
	}

	if xs.fd != 0 {
		err = syscall.Close(xs.fd)
		if err != nil {
			return fmt.Errorf("socket close: %w", err)
		}

		xs.fd = 0
	}

	return nil
}

// completionWorker is started when a socket is created and is responsible for dequeueing the completion ring
// and transfering the free address to the txAddrs chan so they can be re-used
func (xs *XSKSocket) completionWorker() {
	// As long as the completion ring still is mapped
	for xs.completion.mmap != nil {
		// Every tick of the completion ticket, dequeue the whole completion queue
		// and put the frame addrsses on the txAddrs list
		for xs.completion.mmap != nil {
			addr := xs.completion.Dequeue()
			if addr == nil {
				break
			}

			xs.txAddrs <- addrToFrameStart(*addr, xs.settings.FrameSize)
		}

		// TODO auto ajust completion ticket / give control to user to tune it

		<-xs.completionTicker.C
	}
}

// The addresses we get back from the rx ring have offsets due to headspacing, both user configured
// and default headspacing created by the network driver. This function round the address
// to the nearest start of a frame in umem when re-enqueueing the frame address
// https://www.spinics.net/lists/xdp-newbies/msg01479.html
func addrToFrameStart(addr uint64, frameSize int) uint64 {
	return (addr / uint64(frameSize)) * uint64(frameSize)
}

// xskAddrRing is a ring buffer containing decriptors used for the rx and tx rings
type xskDescRing struct {
	xskRing
}

func (dr *xskDescRing) Dequeue() *descriptor {
	producer := (*uint32)(dr.producer)
	consumer := (*uint32)(dr.consumer)

	if (*producer - *consumer) == 0 {
		return nil
	}

	// The linux kernel uses the wraparound of an integer to reset the consumer and
	// producer. And since ring buffers are always a factor of 2 we can just throw away
	// all bits which fall outsize of this size to get a always increasing offset
	// beteen 0 and dr.elemCount
	off := *consumer & (dr.elemCount - 1)
	desc := (*descriptor)(unsafe.Pointer(uintptr(dr.ring) + uintptr(off)*descSize))

	*consumer++

	return desc
}

func (dr *xskDescRing) Enqueue(desc descriptor) error {
	producer := (*uint32)(dr.producer)
	consumer := (*uint32)(dr.consumer)

	// If the diff between producer and consumer is larger than the elem count the buffer is full
	if (*producer - *consumer) == dr.elemCount-1 {
		return errBufferFull
	}

	// The linux kernel uses the wraparound of an integer to reset the consumer and
	// producer. And since ring buffers are always a factor of 2 we can just throw away
	// all bits which fall outsize of this size to get a always increasing offset
	// beteen 0 and dr.elemCount
	off := *producer & (dr.elemCount - 1)

	// Write the address to the current producer pos
	*(*descriptor)(unsafe.Pointer(uintptr(dr.ring) + uintptr(off)*descSize)) = desc

	*producer++

	return nil
}

// xskAddrRing is a ring buffer containing addresses (uint64) used for the fill and completion rings
type xskAddrRing struct {
	xskRing
}

const addrSize = unsafe.Sizeof(uint64(0))

func (ar *xskAddrRing) Dequeue() *uint64 {
	producer := (*uint32)(ar.producer)
	consumer := (*uint32)(ar.consumer)

	if (*producer - *consumer) == 0 {
		return nil
	}

	// The linux kernel uses the wraparound of an integer to reset the consumer and
	// producer. And since ring buffers are always a factor of 2 we can just throw away
	// all bits which fall outsize of this size to get a always increasing offset
	// beteen 0 and ar.elemCount
	off := *consumer & (ar.elemCount - 1)
	addr := (*uint64)(unsafe.Pointer(uintptr(ar.ring) + uintptr(off)*addrSize))

	*consumer++

	return addr
}

var errBufferFull = errors.New("ring buffer is full")

func (ar *xskAddrRing) Enqueue(addr uint64) error {
	producer := (*uint32)(ar.producer)
	consumer := (*uint32)(ar.consumer)

	// If the diff between producer and consumer is larger than the elem count the buffer is full
	if (*producer - *consumer) == ar.elemCount-1 {
		return errBufferFull
	}

	// The linux kernel uses the wraparound of an integer to reset the consumer and
	// producer. And since ring buffers are always a factor of 2 we can just throw away
	// all bits which fall outsize of this size to get a always increasing offset
	// beteen 0 and dr.elemCount
	off := *producer & (ar.elemCount - 1)

	// Write the address to the current producer pos
	*(*uint64)(unsafe.Pointer(uintptr(ar.ring) + uintptr(off)*addrSize)) = addr

	*producer++

	return nil
}

type xskRing struct {
	// Hold a reference to the mmap so we can unmmap it later
	mmap      []byte
	elemCount uint32
	// This double pointer is owned by the producer, it points to the last element in the ring buffer that was added
	producer unsafe.Pointer
	// This double pointer is owned by the consumer, it points to the last element in the ring buffer that was consumed
	consumer unsafe.Pointer
	// A pointer to the start of the ring buffer
	ring  unsafe.Pointer
	flags unsafe.Pointer
}

func (xr *xskRing) Close() error {
	if xr.mmap != nil {
		return syscall.Munmap(xr.mmap)
	}
	xr.mmap = nil

	return nil
}

func newXskRing(mmap []byte, off ringOffset, elemCount uint32) xskRing {
	return xskRing{
		mmap:      mmap,
		consumer:  unsafe.Pointer(&mmap[off.consumer]),
		producer:  unsafe.Pointer(&mmap[off.producer]),
		ring:      unsafe.Pointer(&mmap[off.desc]),
		flags:     unsafe.Pointer(&mmap[off.flags]),
		elemCount: elemCount,
	}
}

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_xdp.h

// struct xdp_umem_reg {
// 	__u64 addr; /* Start of packet data area */
// 	__u64 len; /* Length of packet data area */
// 	__u32 chunk_size;
// 	__u32 headroom;
// 	__u32 flags;
// };
type umemReg struct {
	addr      uint64
	len       uint64
	chunkSize uint32
	headroom  uint32
	flags     uint32
}

// struct xdp_ring_offset {
// 	__u64 producer;
// 	__u64 consumer;
// 	__u64 desc;
// 	__u64 flags;
// };
type ringOffset struct {
	producer uint64
	consumer uint64
	desc     uint64
	flags    uint64
}

type ringOffsetNoFlags struct {
	producer uint64
	consumer uint64
	desc     uint64
}

// struct xdp_mmap_offsets {
// 	struct xdp_ring_offset rx;
// 	struct xdp_ring_offset tx;
// 	struct xdp_ring_offset fr; /* Fill */
// 	struct xdp_ring_offset cr; /* Completion */
// };
type mmapOffsets struct {
	rx ringOffset
	tx ringOffset
	fr ringOffset
	cr ringOffset
}

// struct xdp_desc {
// 	__u64 addr;
// 	__u32 len;
// 	__u32 options;
// };
type descriptor struct {
	addr uint64
	len  uint32
	// options is reserved and not used, setting it to anything other than 0 is invalid in 5.12.2
	// https://elixir.bootlin.com/linux/v5.12.2/source/net/xdp/xsk_queue.h#L141
	options uint32
}

var descSize = unsafe.Sizeof(descriptor{})

// struct sockaddr_xdp {
// 	__u16 sxdp_family;
// 	__u16 sxdp_flags;
// 	__u32 sxdp_ifindex;
// 	__u32 sxdp_queue_id;
// 	__u32 sxdp_shared_umem_fd;
// };
type xdpSockAddr struct {
	sxdpFamily       uint16
	sxdpFlags        uint16
	sxdpIfIndex      uint32
	sxdpQueueID      uint32
	sxdpSharedUmemFD uint32
}

type XSKSettings struct {
	// Size of the umem frames/packet buffers (2048 or 4096)
	FrameSize int
	// Amount of frames/packets which can be used, must be a power of 2
	FrameCount int
	// The index of the network device on which XSK will be used
	NetDevIfIndex int
	// The id of the Queue on which this XSK will be used
	QueueID int
	// How much unused space should be left at the start of each buffer.
	// This can be used to for example encapsulate a packet whichout having to move or copy memory
	Headroom int
	// Is Tx disabled for this socket?
	DisableTx bool
	// Is Rx disabled for this socket?
	DisableRx bool
	// If true, XDP_USE_NEED_WAKEUP is not used. Should be on by default
	// unless there is a reason it doesn't work (like on older kernels)
	DisableNeedWakeup bool
	// If true, zero copy mode is forced. By default zero copy mode is attempted and if not available
	// in the driver will automatically fallback to copy mode.
	ForceZeroCopy bool
	// If true, copy mode is always used and zero copy mode never attempted.
	ForceCopy bool
}

// Same defaults as libbpf https://elixir.bootlin.com/linux/latest/source/tools/lib/bpf/xsk.h#L192
const (
	defaultFrameCount = 4096
	defaultFrameSize  = 4096
)

func NewXSKSocket(settings XSKSettings) (_ *XSKSocket, err error) {
	if settings.FrameCount == 0 {
		settings.FrameCount = defaultFrameCount
	}

	if settings.FrameSize == 0 {
		settings.FrameSize = defaultFrameSize
	}

	if !isPowerOfTwo(settings.FrameCount) {
		return nil, fmt.Errorf("frame count must be a power of 2")
	}

	if settings.FrameSize != 2048 && settings.FrameSize != 4096 {
		// TODO allow frame sizes which are not alligned to 2k but enable
		// XDP_UMEM_UNALIGNED_CHUNK_FLAG when this happens
		return nil, fmt.Errorf("frame size must be 2048 or 4096")
	}

	if settings.DisableTx && settings.DisableRx {
		return nil, fmt.Errorf("tx and rx can't both be disabled")
	}

	if settings.ForceCopy && settings.ForceZeroCopy {
		return nil, fmt.Errorf("can't force both zero-copy and copy mode")
	}

	umemSize := settings.FrameSize * settings.FrameCount
	xskSock := &XSKSocket{
		umem:     make([]byte, umemSize),
		settings: settings,
	}

	xskSock.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("syscall socket: %w", err)
	}
	// If we return with an error, close the socket so we don't leak resources
	defer func() {
		if err != nil {
			xskSock.Close()
		}
	}()

	reg := umemReg{
		addr:      uint64(uintptr(unsafe.Pointer(&xskSock.umem[0]))),
		len:       uint64(len(xskSock.umem)),
		chunkSize: uint32(settings.FrameSize),
		headroom:  uint32(settings.Headroom),
		// TODO flags
	}
	// Register the umem
	err = bpfsys.Setsockopt(
		xskSock.fd,
		unix.SOL_XDP,
		unix.XDP_UMEM_REG,
		unsafe.Pointer(&reg),
		unsafe.Sizeof(reg),
	)
	if err != nil {
		return nil, fmt.Errorf("set sockopt UMEM_REG: %w", err)
	}

	// Assume both are enabled
	rxCount := settings.FrameCount / 2
	txCount := rxCount

	// If tx is disabled
	if settings.DisableTx {
		txCount = 0
		rxCount = settings.FrameCount
	} else if settings.DisableRx {
		txCount = settings.FrameCount
		rxCount = 0
	}

	// Tell the kernel how large the fill ring should be
	err = bpfsys.Setsockopt(
		xskSock.fd,
		unix.SOL_XDP,
		unix.XDP_UMEM_FILL_RING,
		unsafe.Pointer(&rxCount),
		unsafe.Sizeof(rxCount),
	)
	if err != nil {
		return nil, fmt.Errorf("set sockopt XDP_UMEM_FILL_RING: %w", err)
	}

	// Tell the kernel how large the completion ring should be
	err = bpfsys.Setsockopt(
		xskSock.fd,
		unix.SOL_XDP,
		unix.XDP_UMEM_COMPLETION_RING,
		unsafe.Pointer(&txCount),
		unsafe.Sizeof(txCount),
	)
	if err != nil {
		return nil, fmt.Errorf("set sockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	offsets, err := getMMapOffsets(xskSock.fd)
	if err != nil {
		return nil, fmt.Errorf("get mmap offsets: %w", err)
	}

	mmap, err := syscall.Mmap(
		xskSock.fd,
		unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.fr.desc)+rxCount*int(unsafe.Sizeof(uint64(0))),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap fill ring: %w", err)
	}
	xskSock.fill = xskAddrRing{
		xskRing: newXskRing(mmap, offsets.fr, uint32(rxCount)),
	}

	mmap, err = syscall.Mmap(
		xskSock.fd,
		unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.cr.desc)+txCount*int(unsafe.Sizeof(uint64(0))),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap completion ring: %w", err)
	}

	xskSock.completion = xskAddrRing{
		xskRing: newXskRing(mmap, offsets.cr, uint32(txCount)),
	}

	xskSock.txAddrs = make(chan uint64, txCount+1)
	txOffset := rxCount * settings.FrameSize
	// Fill the txAddrs channel with available addresses to use during transmisstion
	for i := 0; i < txCount; i++ {
		xskSock.txAddrs <- uint64(txOffset + i*settings.FrameSize)
	}
	xskSock.completionTicker = time.NewTicker(10 * time.Millisecond)
	go xskSock.completionWorker()

	// Tell the kernel how large the rx ring should be
	err = bpfsys.Setsockopt(
		xskSock.fd,
		unix.SOL_XDP,
		unix.XDP_RX_RING,
		unsafe.Pointer(&rxCount),
		unsafe.Sizeof(rxCount),
	)
	if err != nil {
		return nil, fmt.Errorf("set sockopt XDP_RX_RING: %w", err)
	}

	// Tell the kernel how large the tx ring should be
	err = bpfsys.Setsockopt(
		xskSock.fd,
		unix.SOL_XDP,
		unix.XDP_TX_RING,
		unsafe.Pointer(&txCount),
		unsafe.Sizeof(txCount),
	)
	if err != nil {
		return nil, fmt.Errorf("set sockopt XDP_TX_RING: %w", err)
	}

	mmap, err = syscall.Mmap(
		xskSock.fd,
		unix.XDP_PGOFF_RX_RING,
		int(offsets.rx.desc)+rxCount*int(unsafe.Sizeof(descriptor{})),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap rx ring: %w", err)
	}
	xskSock.rx = xskDescRing{
		xskRing: newXskRing(mmap, offsets.rx, uint32(rxCount)),
	}

	mmap, err = syscall.Mmap(
		xskSock.fd,
		unix.XDP_PGOFF_TX_RING,
		int(offsets.tx.desc)+txCount*int(unsafe.Sizeof(descriptor{})),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE,
	)
	if err != nil {
		return nil, fmt.Errorf("mmap tx ring: %w", err)
	}
	xskSock.tx = xskDescRing{
		xskRing: newXskRing(mmap, offsets.tx, uint32(txCount)),
	}

	var flags uint16
	if !settings.DisableNeedWakeup {
		flags |= unix.XDP_USE_NEED_WAKEUP
	}

	if settings.ForceCopy {
		flags |= unix.XDP_COPY
	}

	if settings.ForceZeroCopy {
		flags |= unix.XDP_ZEROCOPY
	}

	sockAddr := xdpSockAddr{
		sxdpFamily:       unix.AF_XDP,
		sxdpIfIndex:      uint32(settings.NetDevIfIndex),
		sxdpQueueID:      uint32(settings.QueueID),
		sxdpSharedUmemFD: uint32(xskSock.fd),
		sxdpFlags:        flags,
	}
	err = bpfsys.Bind(xskSock.fd, unsafe.Pointer(&sockAddr), bpfsys.Socklen(unsafe.Sizeof(sockAddr)))
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	// Give all Rx frames to the kernel
	for i := 0; i < rxCount; i++ {
		xskSock.fill.Enqueue(uint64(i * settings.FrameSize))
	}
	err = xskSock.wakeupFill()
	if err != nil {
		return nil, fmt.Errorf("wakeupFill: %w", err)
	}
	// NOTE Tx frames are enqueued after they have been filled as a signal to transmit them

	return xskSock, nil
}

func getMMapOffsets(fd int) (offsets mmapOffsets, err error) {
	if kernelsupport.CurrentFeatures.Misc.Has(kernelsupport.KFeatMiscXSKRingFlags) {
		len := bpfsys.Socklen(unsafe.Sizeof(offsets))
		err = bpfsys.Getsockopt(
			fd,
			unix.SOL_XDP,
			unix.XDP_MMAP_OFFSETS,
			unsafe.Pointer(&offsets),
			&len,
		)
		if err != nil {
			return offsets, fmt.Errorf("get sockopt XDP_MMAP_OFFSETS: %w", err)
		}
	} else {
		nfOff, err := getMMapOffsetsNoFlags(fd)
		if err != nil {
			return offsets, fmt.Errorf("no flag offsets: %w", err)
		}
		offsets.rx = ringOffset{
			consumer: nfOff[0].consumer,
			producer: nfOff[0].producer,
			desc:     nfOff[0].desc,
		}
		offsets.tx = ringOffset{
			consumer: nfOff[1].consumer,
			producer: nfOff[1].producer,
			desc:     nfOff[1].desc,
		}
		offsets.cr = ringOffset{
			consumer: nfOff[2].consumer,
			producer: nfOff[2].producer,
			desc:     nfOff[2].desc,
		}
		offsets.fr = ringOffset{
			consumer: nfOff[3].consumer,
			producer: nfOff[3].producer,
			desc:     nfOff[3].desc,
		}
	}

	return offsets, nil
}

func getMMapOffsetsNoFlags(fd int) (offsets [4]ringOffsetNoFlags, err error) {
	len := bpfsys.Socklen(unsafe.Sizeof(offsets))
	err = bpfsys.Getsockopt(
		fd,
		unix.SOL_XDP,
		unix.XDP_MMAP_OFFSETS,
		unsafe.Pointer(&offsets),
		&len,
	)
	if err != nil {
		return offsets, fmt.Errorf("get sockopt XDP_MMAP_OFFSETS: %w", err)
	}

	return offsets, nil
}

func isPowerOfTwo(x int) bool {
	return (x != 0) && ((x & (x - 1)) == 0)
}
