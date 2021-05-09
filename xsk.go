package gobpfld

import (
	"errors"
	"fmt"
	"io"
	"syscall"
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

	rx         xskDescRing
	tx         xskDescRing
	fill       xskAddrRing
	completion xskAddrRing
}

func (xs *XSKSocket) Fd() int {
	return xs.fd
}

// Read implements io.Reader, however we have to implement this with a memory copy which is not ideal
// for efficiency. For zero copy packet access ReadLease should be used.
func (xs *XSKSocket) Read(p []byte) (n int, err error) {
	desc := xs.rx.Dequeue()
	if desc == nil {
		return 0, nil
	}

	// unlike the ReadLease function, we ignore headspace since any benefit is lost
	// during the copy.
	len := copy(p, xs.umem[desc.addr:desc.addr+uint64(desc.len)])

	// The addresses we get back have an offset due to headspacing both user configured
	// and default headspacing created by the network driver so round the address
	// to the nearest start of a frame in umem when re-enqueueing the frame address
	// https://www.spinics.net/lists/xdp-newbies/msg01479.html
	addr := (desc.addr / uint64(xs.settings.FrameSize)) * uint64(xs.settings.FrameSize)
	err = xs.fill.Enqueue(addr)
	if err != nil {
		return len, err
	}

	return len, nil
}

// XSKLease is used to "lease" a piece of buffer memory from the socket and return it after the user
// is done using it. This allows us to implement true zero copy packet access.
// After a XSKLease is released the underlaying array of Data will be repurposed, to avoid strage bugs
// users must use Data or sub-slices of Data after the lease has been released.
type XSKLease struct {
	Data []byte
	// The amount of bytes which are prefixed at the start which don't contain frame data.
	// This headroom can be used to add an extra header(encapsulation) without having to
	// copy or move the existing packet data.
	Headroom  int
	frameAddr uint64
	sock      *XSKSocket
}

// Release releases the leased memory so the kernel can fill it with new data.
func (xl *XSKLease) Release() error {
	// Remove reference to Data since it is invalid from now
	xl.Data = nil
	// Enqueue the address of the frame on the fill queue so it can be reused
	err := xl.sock.fill.Enqueue(xl.frameAddr)
	if err != nil {
		return fmt.Errorf("enqueue fill: %w", err)
	}

	return nil
}

// TODO make XSKLease.WriteBack which will write the leased data.
// this will allow for zero copy encaptulation or replies.
// So instead of enqueueing the address to the fill ring we enqueue a new descriptor to the
// tx ring with the correct address and length.
// We then need to dequeue one frame from the completion ring and enqueue it in the fill ring
// to equalize the amount of frames in circulation between tx and rx

func (xs *XSKSocket) ReadLease() (lease *XSKLease, err error) {
	desc := xs.rx.Dequeue()
	if desc == nil {
		return nil, nil
	}

	return &XSKLease{
		Headroom:  xs.settings.Headroom,
		Data:      xs.umem[desc.addr-uint64(xs.settings.Headroom) : desc.addr+uint64(desc.len)],
		frameAddr: (desc.addr / uint64(xs.settings.FrameSize)) * uint64(xs.settings.FrameSize),
		sock:      xs,
	}, nil
}

// Write implements io.Writer. The interface requires us to copy p into umem which is not
// optimal for speed.
func (xs *XSKSocket) Write(p []byte) (n int, err error) {
	addr := xs.completion.Dequeue()
	if addr == nil {
		return 0, fmt.Errorf("transmit queue is full")
	}

	if len(p) > xs.settings.FrameSize {
		return 0, fmt.Errorf("data is larget than frame size of %d", xs.settings.FrameSize)
	}

	len := copy(xs.umem[*addr:*addr+uint64(len(p))], p)

	// TODO add options support
	err = xs.tx.Enqueue(descriptor{
		addr: *addr,
		len:  uint32(len),
	})
	if err != nil {
		return 0, fmt.Errorf("tx enqueue: %w", err)
	}

	// TODO only use send syscall to if needed (when ring has XDP_RING_NEED_WAKEUP)
	err = bpfsys.Sendto(xs.fd, nil, syscall.MSG_DONTWAIT, unsafe.Pointer(&bpfsys.Zero), bpfsys.Socklen(0))
	if err != nil {
		return 0, fmt.Errorf("syscall sendto: %w", err)
	}

	fmt.Printf("producer: %d, consumer: %d\n", *(*uint32)(xs.tx.producer), *(*uint32)(xs.tx.consumer))

	return len, nil
}

func (xs *XSKSocket) Close() error {
	// TODO return errors we get from syscall? in a way we still close all resources

	if xs.fd != 0 {
		syscall.Close(xs.fd)
		xs.fd = 0
	}

	xs.rx.Close()
	xs.tx.Close()
	xs.fill.Close()
	xs.completion.Close()

	return nil
}

// xskAddrRing is a ring buffer containing decriptors used for the rx and tx rings
type xskDescRing struct {
	xskRing
}

func (dr *xskDescRing) Dequeue() *descriptor {
	producer := (*uint32)(dr.producer)
	consumer := (*uint32)(dr.consumer)

	// TODO add epoll/poll/select support
	// TODO add runtime reconfigurable read timeouts like with package net tcp connections

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

	// TODO add epoll/poll/select support
	// TODO add runtime reconfigurable write timeouts like with package net tcp connections

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

	// TODO add epoll/poll/select support
	// TODO add runtime reconfigurable read timeouts like with package net tcp connections

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

	// TODO add epoll/poll/select support
	// TODO add runtime reconfigurable write timeouts like with package net tcp connections

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

func (xr *xskRing) Close() {
	if xr.mmap != nil {
		syscall.Munmap(xr.mmap)
	}
	xr.mmap = nil
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
	addr    uint64
	len     uint32
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
}

func NewXSKSocket(settings XSKSettings) (_ *XSKSocket, err error) {
	if !isPowerOfTwo(settings.FrameCount) {
		return nil, fmt.Errorf("frame count must be a power of 2")
	}

	if settings.FrameSize != 2048 && settings.FrameSize != 4096 {
		return nil, fmt.Errorf("frame size must be 2048 or 4096")
	}

	if settings.DisableTx && settings.DisableRx {
		return nil, fmt.Errorf("tx and rx can't both be disabled")
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

	txOffset := rxCount * settings.FrameSize
	// Fill the entire completion queue. Since we consume an address from the completion queue
	// opon writing we need to initialize the queue this way.
	// After this the kernel will replenish the queue after the frame has been sent.
	for i := 0; i < txCount; i++ {
		xskSock.completion.Enqueue(uint64(txOffset + i*settings.FrameSize))
	}

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

	sockAddr := xdpSockAddr{
		sxdpFamily:       unix.AF_XDP,
		sxdpIfIndex:      uint32(settings.NetDevIfIndex),
		sxdpQueueID:      uint32(settings.QueueID),
		sxdpSharedUmemFD: uint32(xskSock.fd),
		//TODO flags
	}
	err = bpfsys.Bind(xskSock.fd, unsafe.Pointer(&sockAddr), bpfsys.Socklen(unsafe.Sizeof(sockAddr)))
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	// Give all Rx frames to the kernel
	for i := 0; i < rxCount; i++ {
		xskSock.fill.Enqueue(uint64(i * settings.FrameSize))
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
