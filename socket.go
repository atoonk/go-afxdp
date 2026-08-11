//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Portions Copyright 2019 Asavie Technologies Ltd.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The four AF_XDP rings are shared with the kernel; the producer/consumer
// indices must be accessed with acquire/release ordering, not plain loads and
// stores. We are the producer for the fill and tx rings (write descriptors,
// then publish the index) and the consumer for the rx and completion rings
// (load the index, then read descriptors). On x86's strong memory model plain
// access happens to work, but on weak-memory CPUs (ARM/Graviton) it does not —
// the kernel could see a bumped producer before our descriptor writes, or we
// could read a descriptor the kernel hasn't finished writing. atomic.Load/Store
// give the required ordering (and compile to plain MOV / LDAR/STLR).
func ldIdx(p *uint32) uint32    { return atomic.LoadUint32(p) }
func stIdx(p *uint32, v uint32) { atomic.StoreUint32(p, v) }

// Desc is an AF_XDP rx/tx descriptor: a frame address within the UMEM and a
// length. It is layout-compatible with unix.XDPDesc.
type Desc unix.XDPDesc

// Flags is the kernel's per-ring flag word (XDP_MMAP_OFFSETS exposes it next to
// the producer/consumer indices). Its only defined bit is XDP_RING_NEED_WAKEUP:
// the driver sets it to say "I have stopped polling, wake me when you have
// refilled". Ignoring it is why a driver bound WITHOUT XDP_USE_NEED_WAKEUP
// spins: see NeedsWakeupRx.
type umemRing struct {
	Producer *uint32
	Consumer *uint32
	Flags    *uint32
	Descs    []uint64
}

type rxTxRing struct {
	Producer *uint32
	Consumer *uint32
	Flags    *uint32
	Descs    []Desc
}

// Socket is an AF_XDP socket — commonly called an "XSK" (XDP socket) — bound to
// one (interface, queue) pair. Its methods use the receiver name xsk, the
// conventional shorthand for an XDP socket throughout the kernel and libbpf
// code, and you'll see local variables named xsk in the examples for the same
// reason.
//
// A Socket owns a UMEM (the memory region shared with the kernel that holds
// packet frames) and the four rings that move frames to and from the kernel.
//
// Concurrency model. A Socket is safe for exactly one receive goroutine
// running concurrently with one transmit goroutine, with no locking — this is
// the guarantee the upstream asavie/xdp could not make. The receive side
// (Fill, Poll, Receive, Recycle) and the transmit side (Alloc, Transmit,
// Complete, Kick) own disjoint frame pools and disjoint rings, so they never
// touch shared mutable state.
//
//   - If multiple goroutines transmit on one Socket, guard the transmit-side
//     calls with your own mutex (the receive side still needs none), or give
//     each producer its own Socket/queue via a Fleet.
//   - The receive side is single-consumer; likewise guard it if you fan out
//     receive across goroutines.
//   - Close is the exception: it may be called from any goroutine at any
//     time. It wakes a blocked Poll (which returns net.ErrClosed) and waits
//     for in-flight calls to finish before releasing the shared memory.
type Socket struct {
	fd      int
	ifindex int
	options Options
	umem    []byte

	// Shutdown machinery. closing flips once, in Close. wakeFd is an eventfd
	// included in Poll's fd set so Close can wake a blocked poller. ops counts
	// in-flight method calls; Close waits for it to drain before unmapping the
	// rings those methods read, so a concurrent Close is safe rather than a
	// use-after-munmap.
	closing atomic.Bool
	ops     atomic.Int64
	wakeFd  int

	// ringMems holds the raw mmap regions backing the four rings so Close can
	// munmap them; the ring structs below alias into these mappings.
	ringMems [][]byte

	fillRing       umemRing
	rxRing         rxTxRing
	txRing         rxTxRing
	completionRing umemRing

	// Receive-side state, owned by the receive goroutine.
	rxPool     *framePool
	rxScratch  []Desc
	popScratch []uint64
	numFilled  int

	// Multi-buffer receive state, owned by the receive goroutine. A chained
	// packet can straddle two ReceivePackets calls when the batch boundary
	// lands mid-packet, so the fragments seen so far are held here until the
	// descriptor that ends the packet arrives. See ReceivePackets.
	pktScratch []Packet
	pktPartial []Desc
	pktDescs   []Desc

	// Transmit-side state, owned by the transmit goroutine.
	txPool         *framePool
	txScratch      []Desc
	txPopScratch   []uint64
	numTransmitted int

	// Kick accounting: written on the transmit path, read by Stats from its
	// own goroutine, hence atomic rather than guarded by statsMu.
	statKicks           atomic.Uint64
	statKicksSuppressed atomic.Uint64

	// Receive-path syscall accounting, same rationale as the kick counters.
	statPolls   atomic.Uint64
	statRxKicks atomic.Uint64

	// Stats-side state: the kernel's ring indices are 32-bit and wrap every
	// 2^32 packets (~5 minutes at 10G line rate), so Stats extends them to
	// 64-bit here. Guarded by statsMu — only the Stats path takes it, the
	// rx/tx data paths never do.
	statsMu         sync.Mutex
	statFilled      ringCounter
	statReceived    ringCounter
	statTransmitted ringCounter
	statCompleted   ringCounter
}

// ringCounter extends a wrapping 32-bit ring index into a monotonic 64-bit
// count. The uint32 subtraction makes wrap-around come out right, provided
// fewer than 2^32 packets pass between updates.
type ringCounter struct {
	last  uint32
	total uint64
}

func (c *ringCounter) update(cur uint32) uint64 {
	c.total += uint64(cur - c.last)
	c.last = cur
	return c.total
}

// incref registers an in-flight operation, refusing if the Socket is closing.
// Methods that touch the fd or the ring mappings bracket themselves with
// incref/decref so Close can wait for them before tearing those down. The
// double check closes the race where Close flips the flag between our check
// and our increment.
func (xsk *Socket) incref() bool {
	if xsk.closing.Load() {
		return false
	}
	xsk.ops.Add(1)
	if xsk.closing.Load() {
		xsk.ops.Add(-1)
		return false
	}
	return true
}

func (xsk *Socket) decref() { xsk.ops.Add(-1) }

// NewSocket creates an AF_XDP socket on the given interface index and queue ID.
// Pass nil options for defaults (see DefaultOptions). After creating the
// socket you must register its FD with an attached Program (or use OpenFleet,
// which does both for every queue).
func NewSocket(ifindex, queueID int, options *Options) (*Socket, error) {
	opts := options.withDefaults()
	if opts.NumFrames <= 0 {
		return nil, fmt.Errorf("afxdp: NumFrames must be > 0, got %d", opts.NumFrames)
	}
	if opts.TxFrames <= 0 || opts.TxFrames >= opts.NumFrames {
		return nil, fmt.Errorf("afxdp: TxFrames must be in (0, NumFrames), got %d of %d", opts.TxFrames, opts.NumFrames)
	}
	for name, v := range map[string]int{
		"FillRingNumDescs":       opts.FillRingNumDescs,
		"CompletionRingNumDescs": opts.CompletionRingNumDescs,
		"RxRingNumDescs":         opts.RxRingNumDescs,
		"TxRingNumDescs":         opts.TxRingNumDescs,
	} {
		if v != 0 && v&(v-1) != 0 {
			return nil, fmt.Errorf("afxdp: %s must be a power of two, got %d", name, v)
		}
	}
	// The fill ring can only ever hold as many buffers as the receive pool
	// (NumFrames - TxFrames) has to give it. A fill ring larger than the rx pool
	// is silently capped to the pool size, which reads as "I asked for a deep
	// ring but throughput is still low" — a perf cliff that's easy to hit and
	// hard to see. Reject it so the misconfiguration is loud, not silent.
	if rxPool := opts.NumFrames - opts.TxFrames; opts.FillRingNumDescs > rxPool {
		return nil, fmt.Errorf("afxdp: FillRingNumDescs (%d) exceeds the rx frame pool (%d = NumFrames-TxFrames); "+
			"raise NumFrames or lower TxFrames (e.g. WithReceiveHeavy) so the fill ring can be backed",
			opts.FillRingNumDescs, rxPool)
	}

	xsk := &Socket{fd: -1, ifindex: ifindex, options: opts, wakeFd: -1}

	var err error
	xsk.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("afxdp: AF_XDP socket: %w", err)
	}

	// The wake eventfd rides along in Poll's fd set so Close can interrupt a
	// blocked poller instead of closing the socket fd out from under it.
	xsk.wakeFd, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: eventfd: %w", err)
	}

	xsk.umem, err = syscall.Mmap(-1, 0, opts.NumFrames*opts.FrameSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: mmap UMEM: %w", err)
	}

	xdpUmemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&xsk.umem[0]))),
		Len:      uint64(len(xsk.umem)),
		Size:     uint32(opts.FrameSize),
		Headroom: 0,
	}
	if rc, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&xdpUmemReg)), unsafe.Sizeof(xdpUmemReg), 0); rc != 0 {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: XDP_UMEM_REG: %w", errno)
	}

	if err = syscall.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, opts.FillRingNumDescs); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: XDP_UMEM_FILL_RING: %w", err)
	}
	if err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, opts.CompletionRingNumDescs); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: XDP_UMEM_COMPLETION_RING: %w", err)
	}

	hasRx := opts.RxRingNumDescs > 0
	hasTx := opts.TxRingNumDescs > 0
	if !hasRx && !hasTx {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: RxRingNumDescs and TxRingNumDescs cannot both be zero")
	}
	if hasRx {
		if err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_RX_RING, opts.RxRingNumDescs); err != nil {
			xsk.Close()
			return nil, fmt.Errorf("afxdp: XDP_RX_RING: %w", err)
		}
	}
	if hasTx {
		if err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_TX_RING, opts.TxRingNumDescs); err != nil {
			xsk.Close()
			return nil, fmt.Errorf("afxdp: XDP_TX_RING: %w", err)
		}
	}

	var offsets unix.XDPMmapOffsets
	vallen := uint32(unsafe.Sizeof(offsets))
	if rc, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)), uintptr(unsafe.Pointer(&vallen)), 0); rc != 0 {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: XDP_MMAP_OFFSETS: %w", errno)
	}

	// Map each ring the kernel allocated and slice its descriptor array. The
	// mappings are retained in ringMems so Close can munmap them.
	mapRing := func(pgoff int64, size int, what string) (unsafe.Pointer, error) {
		mem, err := syscall.Mmap(xsk.fd, pgoff, size,
			syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED|syscall.MAP_POPULATE)
		if err != nil {
			return nil, fmt.Errorf("afxdp: mmap %s ring: %w", what, err)
		}
		xsk.ringMems = append(xsk.ringMems, mem)
		return unsafe.Pointer(&mem[0]), nil
	}

	// Fill ring.
	base, err := mapRing(unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.Fr.Desc+uint64(opts.FillRingNumDescs)*uint64(unsafe.Sizeof(uint64(0)))), "fill")
	if err != nil {
		xsk.Close()
		return nil, err
	}
	xsk.fillRing.Producer = (*uint32)(unsafe.Add(base, offsets.Fr.Producer))
	xsk.fillRing.Consumer = (*uint32)(unsafe.Add(base, offsets.Fr.Consumer))
	xsk.fillRing.Flags = (*uint32)(unsafe.Add(base, offsets.Fr.Flags))
	xsk.fillRing.Descs = unsafe.Slice((*uint64)(unsafe.Add(base, offsets.Fr.Desc)), opts.FillRingNumDescs)

	// Completion ring.
	base, err = mapRing(unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.Cr.Desc+uint64(opts.CompletionRingNumDescs)*uint64(unsafe.Sizeof(uint64(0)))), "completion")
	if err != nil {
		xsk.Close()
		return nil, err
	}
	xsk.completionRing.Producer = (*uint32)(unsafe.Add(base, offsets.Cr.Producer))
	xsk.completionRing.Consumer = (*uint32)(unsafe.Add(base, offsets.Cr.Consumer))
	xsk.completionRing.Flags = (*uint32)(unsafe.Add(base, offsets.Cr.Flags))
	xsk.completionRing.Descs = unsafe.Slice((*uint64)(unsafe.Add(base, offsets.Cr.Desc)), opts.CompletionRingNumDescs)

	if hasRx {
		base, err = mapRing(unix.XDP_PGOFF_RX_RING,
			int(offsets.Rx.Desc+uint64(opts.RxRingNumDescs)*uint64(unsafe.Sizeof(Desc{}))), "rx")
		if err != nil {
			xsk.Close()
			return nil, err
		}
		xsk.rxRing.Producer = (*uint32)(unsafe.Add(base, offsets.Rx.Producer))
		xsk.rxRing.Consumer = (*uint32)(unsafe.Add(base, offsets.Rx.Consumer))
		xsk.rxRing.Flags = (*uint32)(unsafe.Add(base, offsets.Rx.Flags))
		xsk.rxRing.Descs = unsafe.Slice((*Desc)(unsafe.Add(base, offsets.Rx.Desc)), opts.RxRingNumDescs)
		xsk.rxScratch = make([]Desc, 0, opts.RxRingNumDescs)
	}

	if hasTx {
		base, err = mapRing(unix.XDP_PGOFF_TX_RING,
			int(offsets.Tx.Desc+uint64(opts.TxRingNumDescs)*uint64(unsafe.Sizeof(Desc{}))), "tx")
		if err != nil {
			xsk.Close()
			return nil, err
		}
		xsk.txRing.Producer = (*uint32)(unsafe.Add(base, offsets.Tx.Producer))
		xsk.txRing.Consumer = (*uint32)(unsafe.Add(base, offsets.Tx.Consumer))
		xsk.txRing.Flags = (*uint32)(unsafe.Add(base, offsets.Tx.Flags))
		xsk.txRing.Descs = unsafe.Slice((*Desc)(unsafe.Add(base, offsets.Tx.Desc)), opts.TxRingNumDescs)
		xsk.txScratch = make([]Desc, 0, opts.TxRingNumDescs)
	}

	// Split the UMEM frames into disjoint receive and transmit pools.
	// Receive frames come first: [0, rxFrames). Transmit frames follow:
	// [rxFrames, NumFrames).
	rxFrames := opts.NumFrames - opts.TxFrames
	xsk.rxPool = newFramePool(0, rxFrames, opts.FrameSize)
	xsk.txPool = newFramePool(rxFrames, opts.TxFrames, opts.FrameSize)
	xsk.popScratch = make([]uint64, 0, opts.FillRingNumDescs)

	// Populate the fill ring BEFORE bind. Bind is what activates the driver's
	// XSK receive queue, and a zero-copy driver starts allocating RX buffers
	// from the fill ring the moment it activates: activated against an empty
	// ring, mlx5 (observed on 6.8, ConnectX at 24 queues) intermittently
	// wedges the queue in a permanent buff_alloc_err loop that no later fill
	// recovers -- the socket looks bound and healthy but never delivers a
	// packet. The kernel's own xdpsock sample fills before bind for the same
	// reason.
	xsk.Fill(opts.FillRingNumDescs)

	sa := &unix.SockaddrXDP{
		Flags:   opts.BindFlags,
		Ifindex: uint32(ifindex),
		QueueID: uint32(queueID),
	}
	if err = unix.Bind(xsk.fd, sa); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: bind queue %d: %w", queueID, err)
	}

	return xsk, nil
}

// FD returns the socket file descriptor, e.g. for registering with a Program
// or for your own polling.
func (xsk *Socket) FD() int { return xsk.fd }

// GetFrame returns the UMEM buffer for a descriptor. Writing to the returned
// slice writes the frame that will be transmitted (or reads what was
// received). The slice aliases the UMEM; do not retain it past the point you
// hand the descriptor back to the kernel.
func (xsk *Socket) GetFrame(d Desc) []byte {
	return xsk.umem[d.Addr : d.Addr+uint64(d.Len)]
}

// UMEM returns the socket's entire UMEM as one slice (NumFrames*FrameSize
// bytes; frame i occupies [i*FrameSize, (i+1)*FrameSize)). It lets an
// application build its own frame-granular structures — e.g. a forwarding
// dataplane whose packet-buffer pool IS the UMEM, avoiding a copy on
// receive. The same aliasing rules as GetFrame apply, per frame: a frame's
// bytes are yours only between receiving it (Receive) and handing it back
// (Recycle/Fill), or between Alloc and Transmit on the transmit side.
func (xsk *Socket) UMEM() []byte { return xsk.umem }

// FrameSize returns the UMEM frame size the socket was configured with
// (after defaulting and driver-specific adjustment, e.g. 4096 on ENA) —
// the stride for interpreting UMEM() frame-by-frame.
func (xsk *Socket) FrameSize() int { return xsk.options.FrameSize }

func (xsk *Socket) frameBase(addr uint64) uint64 {
	return addr - (addr % uint64(xsk.options.FrameSize))
}

// ---------------- Receive side (one receive goroutine) ----------------

// Fill moves up to n free receive frames onto the fill ring, where the kernel
// will write incoming packets into them. It returns the number of frames
// submitted, which may be less than n if the receive pool or the fill ring is
// short on space. Call it before Poll so the kernel always has buffers.
func (xsk *Socket) Fill(n int) int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	if free := xsk.NumFreeFillSlots(); n > free {
		n = free
	}
	xsk.popScratch = xsk.rxPool.pop(n, xsk.popScratch[:0])
	addrs := xsk.popScratch
	if len(addrs) == 0 {
		return 0
	}
	prod := ldIdx(xsk.fillRing.Producer)
	mask := uint32(xsk.options.FillRingNumDescs - 1)
	for _, addr := range addrs {
		xsk.fillRing.Descs[prod&mask] = addr
		prod++
	}
	stIdx(xsk.fillRing.Producer, prod) // release: descriptors written above are now visible
	xsk.numFilled += len(addrs)
	return len(addrs)
}

// ringNeedsWakeup reports the XDP_RING_NEED_WAKEUP bit. A nil Flags pointer
// means the ring was mapped by a kernel too old to expose it, in which case the
// driver never sleeps and no wakeup is needed.
func ringNeedsWakeup(flags *uint32) bool {
	return flags != nil && atomic.LoadUint32(flags)&unix.XDP_RING_NEED_WAKEUP != 0
}

// NeedsWakeupRx reports whether the driver has stopped polling the receive side
// and is waiting to be woken.
//
// This is the whole point of binding with XDP_USE_NEED_WAKEUP (WithNeedWakeup).
// WITHOUT that flag, a driver that cannot get buffers from the fill ring has no
// way to say so: ixgbe_clean_rx_irq_zc returns `budget` instead of the real
// packet count, so napi_complete is never called, NAPI reschedules itself
// immediately, and ksoftirqd spins in net_rx_action forever — on this hardware
// that burned 65% of a 12-core box at ZERO packets per second, with every poll
// reporting work==budget. WITH the flag the driver returns the true count, NAPI
// completes and sleeps, and it is our job to wake it after refilling. Poll does
// that automatically; call this directly only if you drive the rings yourself.
func (xsk *Socket) NeedsWakeupRx() bool { return ringNeedsWakeup(xsk.fillRing.Flags) }

// NeedsWakeupTx reports whether the driver has stopped polling the transmit
// side and needs a Kick to resume. Only meaningful with WithNeedWakeup.
func (xsk *Socket) NeedsWakeupTx() bool { return ringNeedsWakeup(xsk.txRing.Flags) }

// Poll blocks until the kernel has received frames, the timeout elapses, or
// the Socket is closed. A negative timeout waits forever; zero returns
// immediately. It returns the number of received frames now available to
// Receive. Poll only watches the receive direction; the transmit side drives
// completions via Complete/Kick.
//
// Poll doubles as the RX wakeup: when the driver has parked itself (see
// NeedsWakeupRx) the poll(2) call is what restarts its NAPI poll, so a receive
// loop that calls Poll whenever it finds no packets needs no other change to
// work correctly with WithNeedWakeup.
//
// Close from another goroutine wakes a blocked Poll, which then returns
// net.ErrClosed — so a receive loop that stops on any Poll error shuts down
// cleanly.
func (xsk *Socket) Poll(timeout time.Duration) (numReceived int, err error) {
	if !xsk.incref() {
		return 0, net.ErrClosed
	}
	defer xsk.decref()
	// Nothing in the fill ring means the kernel has nowhere to put a packet, so
	// blocking would be pointless — EXCEPT when the driver is parked waiting on
	// us, where the poll(2) below is the only thing that will restart it.
	if xsk.numFilled == 0 && !xsk.NeedsWakeupRx() {
		return 0, nil
	}
	ms := -1
	if timeout >= 0 {
		ms = int(timeout / time.Millisecond)
		if ms == 0 && timeout > 0 {
			ms = 1 // don't turn a small positive timeout into "don't block"
		}
	}
	pfds := [2]unix.PollFd{
		{Fd: int32(xsk.fd), Events: unix.POLLIN},
		{Fd: int32(xsk.wakeFd), Events: unix.POLLIN},
	}
	xsk.statPolls.Add(1)
	for err = unix.EINTR; err == unix.EINTR; {
		_, err = unix.Poll(pfds[:], ms)
	}
	if err != nil {
		return 0, err
	}
	if pfds[1].Revents != 0 { // woken by Close
		return 0, net.ErrClosed
	}
	return xsk.NumReceived(), nil
}

// Receive consumes up to max received descriptors from the rx ring. The
// returned slice is owned by the Socket and reused on the next Receive call;
// copy out anything you need to keep. After you are done reading the frames,
// return them with Recycle so they can be filled again.
func (xsk *Socket) Receive(max int) []Desc {
	if !xsk.incref() {
		return nil
	}
	defer xsk.decref()
	avail := xsk.NumReceived()
	if max > avail {
		max = avail
	}
	descs := xsk.rxScratch[:0]
	cons := ldIdx(xsk.rxRing.Consumer)
	mask := uint32(xsk.options.RxRingNumDescs - 1)
	for i := 0; i < max; i++ {
		descs = append(descs, xsk.rxRing.Descs[cons&mask])
		cons++
	}
	stIdx(xsk.rxRing.Consumer, cons) // release: kernel may reuse these slots now
	xsk.numFilled -= max
	xsk.rxScratch = descs
	return descs
}

// Recycle returns received frames to the receive pool so a later Fill can hand
// them back to the kernel. Pass the descriptors you got from Receive once you
// have finished reading their frames.
func (xsk *Socket) Recycle(descs []Desc) {
	for _, d := range descs {
		xsk.rxPool.push(xsk.frameBase(d.Addr))
	}
}

// NumFreeFillSlots returns how many descriptors can still be put on the fill
// ring before it is full.
func (xsk *Socket) NumFreeFillSlots() int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	prod := ldIdx(xsk.fillRing.Producer)
	cons := ldIdx(xsk.fillRing.Consumer)
	max := uint32(xsk.options.FillRingNumDescs)
	if n := max - (prod - cons); n <= max {
		return int(n)
	}
	return int(max)
}

// NumReceived returns how many received descriptors are waiting on the rx ring.
func (xsk *Socket) NumReceived() int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	n := ldIdx(xsk.rxRing.Producer) - ldIdx(xsk.rxRing.Consumer) // acquire on producer
	if max := uint32(xsk.options.RxRingNumDescs); n > max {
		n = max
	}
	return int(n)
}

// NumFilled returns how many frames are currently posted on the fill ring
// awaiting incoming packets.
func (xsk *Socket) NumFilled() int { return xsk.numFilled }

// FreeRxFrames returns how many receive frames are idle in the receive pool
// (neither on the fill ring nor held by the application).
func (xsk *Socket) FreeRxFrames() int { return xsk.rxPool.len() }

// ---------------- Transmit side (one transmit goroutine) ----------------

// Alloc reserves up to n transmit frames and returns descriptors for them.
// Build your packet into GetFrame(desc), set desc.Len to the packet length,
// then pass the descriptors to Transmit. The returned slice is owned by the
// Socket and reused by the next Alloc; do not retain it.
//
// Alloc returns fewer than n descriptors (possibly zero) when the transmit pool
// is drained (call Complete to reclaim sent frames first) OR when the tx ring is
// full. Capping to the free ring space means Transmit can always queue every
// descriptor Alloc returns, so none are dropped and leaked back out of the pool.
func (xsk *Socket) Alloc(n int) []Desc {
	if !xsk.incref() {
		return nil
	}
	defer xsk.decref()
	if free := xsk.NumFreeTxSlots(); n > free {
		n = free
	}
	xsk.txPopScratch = xsk.txPool.pop(n, xsk.txPopScratch[:0])
	xsk.txScratch = xsk.txScratch[:0]
	for _, addr := range xsk.txPopScratch {
		xsk.txScratch = append(xsk.txScratch, Desc{Addr: addr, Len: uint32(xsk.options.FrameSize)})
	}
	return xsk.txScratch
}

// Transmit puts the given descriptors on the tx ring and kicks the kernel to
// send them. It returns how many were actually queued (capped by free tx ring
// space). Frames that are queued are owned by the kernel until they appear on
// the completion ring; reclaim them with Complete.
func (xsk *Socket) Transmit(descs []Desc) int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	if free := xsk.NumFreeTxSlots(); len(descs) > free {
		descs = descs[:free]
	}
	if len(descs) == 0 {
		return 0
	}
	prod := ldIdx(xsk.txRing.Producer)
	mask := uint32(xsk.options.TxRingNumDescs - 1)
	for _, d := range descs {
		xsk.txRing.Descs[prod&mask] = d
		prod++
	}
	stIdx(xsk.txRing.Producer, prod) // release: descriptors written above are now visible
	xsk.numTransmitted += len(descs)
	if xsk.kickNeeded() {
		_ = xsk.Kick()
	} else {
		xsk.statKicksSuppressed.Add(1)
	}
	return len(descs)
}

// kickNeeded reports whether transmitting requires a kick syscall right now.
// Without XDP_USE_NEED_WAKEUP the kernel never advertises its state, so every
// transmit must kick. With it, the tx ring flag says whether the driver has
// parked: a zero-copy driver actively draining the ring clears the flag and
// needs no syscall at all, which is where need-wakeup pays for itself (copy
// mode keeps the flag set essentially always, so it still kicks every time).
func (xsk *Socket) kickNeeded() bool {
	return xsk.options.BindFlags&unix.XDP_USE_NEED_WAKEUP == 0 || xsk.NeedsWakeupTx()
}

// Kick asks the kernel to process the tx ring. Transmit calls it for you after
// queueing frames (skipping the syscall when a need-wakeup bind shows the
// driver already awake), so you normally don't call it directly — with one
// important exception: if the tx ring fills up (NumFreeTxSlots returns 0) so
// you can't Transmit more, call Kick anyway to keep the kernel draining the
// ring and producing completions. In copy mode the kernel will not drain the
// ring without a kick, so a tight "if full, continue" loop that skips the kick
// deadlocks. (In zero-copy the driver drains on its own, but kicking is
// harmless.)
func (xsk *Socket) Kick() error {
	if !xsk.incref() {
		return net.ErrClosed
	}
	defer xsk.decref()
	// Copy-mode transmit processes only a bounded batch of descriptors per
	// syscall (TX_BATCH_SIZE in net/xdp/xsk.c, 16 or 32 depending on kernel
	// version) and returns EAGAIN while the tx ring still holds more, so a
	// single kick is not guaranteed to drain a large batch — retry until the
	// kernel stops asking. The retry budget covers a full tx ring at the
	// smallest batch size; it exists because EAGAIN can also mean a condition
	// a kick cannot clear (a busy device queue, or on some kernel versions a
	// full completion ring that only Complete relieves), where retrying
	// forever would wedge the transmit goroutine. (Watching the ring's
	// consumer index instead does not work: the kernel publishes it lazily, a
	// syscall behind its actual progress.)
	retries := xsk.options.TxRingNumDescs/16 + 8
	for {
		xsk.statKicks.Add(1)
		rc, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(xsk.fd),
			0, 0, uintptr(unix.MSG_DONTWAIT), 0, 0)
		if rc == 0 {
			return nil
		}
		switch errno {
		case unix.EINTR:
			continue
		case unix.EAGAIN:
			if retries--; retries > 0 {
				continue
			}
			return nil
		case unix.EBUSY:
			// Completed but not yet sent; non-fatal.
			return nil
		default:
			return fmt.Errorf("afxdp: sendto kick: %w", errno)
		}
	}
}

// WakeupRx is Kick's receive-side twin: it wakes a driver that has parked
// with the fill-ring NEED_WAKEUP flag set, so it resumes posting the
// descriptors a preceding Fill made available. Poll performs this wakeup as a
// side effect, which hides the contract from callers that block; a caller
// that drives the rings directly (Fill without ever blocking in Poll) MUST
// call this after refilling whenever NeedsWakeupRx reports true, or the newly
// filled descriptors sit unposted until its next idle Poll -- the NIC then
// drops arriving packets for want of RX descriptors (rx_out_of_buffer) while
// the fill ring is provably full. Measured on a 48-core mlx5 router: the
// workers' idle-poll rate became the descriptor-posting clock, capping
// delivery at ~5.5M pps with the box two-thirds idle.
//
// The syscall is a zero-length non-blocking recvfrom, the canonical XSK RX
// wakeup. Call only when NeedsWakeupRx is true; the flag check is one atomic
// load, so the syscall is paid only when the driver is actually parked.
func (xsk *Socket) WakeupRx() error {
	if !xsk.incref() {
		return net.ErrClosed
	}
	defer xsk.decref()
	xsk.statRxKicks.Add(1)
	for {
		_, _, errno := unix.Syscall6(unix.SYS_RECVFROM, uintptr(xsk.fd),
			0, 0, uintptr(unix.MSG_DONTWAIT), 0, 0)
		switch errno {
		case 0, unix.EAGAIN: // EWOULDBLOCK == EAGAIN on Linux
			return nil // woken; EAGAIN just means "nothing to read", which is fine
		case unix.EINTR:
			continue
		default:
			return fmt.Errorf("afxdp: recvfrom rx wakeup: %w", errno)
		}
	}
}

// Complete reclaims up to n transmitted frames from the completion ring and
// returns them to the transmit pool, making them available to Alloc again.
// It returns how many frames were reclaimed.
func (xsk *Socket) Complete(n int) int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	avail := xsk.NumCompleted()
	if n > avail {
		n = avail
	}
	cons := ldIdx(xsk.completionRing.Consumer)
	mask := uint32(xsk.options.CompletionRingNumDescs - 1)
	for i := 0; i < n; i++ {
		addr := xsk.completionRing.Descs[cons&mask]
		cons++
		xsk.txPool.push(xsk.frameBase(addr))
	}
	stIdx(xsk.completionRing.Consumer, cons) // release: kernel may reuse these slots now
	xsk.numTransmitted -= n
	return n
}

// NumFreeTxSlots returns how many descriptors can still be put on the tx ring.
func (xsk *Socket) NumFreeTxSlots() int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	prod := ldIdx(xsk.txRing.Producer)
	cons := ldIdx(xsk.txRing.Consumer)
	max := uint32(xsk.options.TxRingNumDescs)
	if n := max - (prod - cons); n <= max {
		return int(n)
	}
	return int(max)
}

// NumCompleted returns how many transmitted frames are waiting on the
// completion ring to be reclaimed by Complete.
func (xsk *Socket) NumCompleted() int {
	if !xsk.incref() {
		return 0
	}
	defer xsk.decref()
	n := ldIdx(xsk.completionRing.Producer) - ldIdx(xsk.completionRing.Consumer) // acquire on producer
	if max := uint32(xsk.options.CompletionRingNumDescs); n > max {
		n = max
	}
	return int(n)
}

// NumTransmitted returns how many frames are on the tx ring not yet confirmed
// sent (i.e. not yet on the completion ring).
func (xsk *Socket) NumTransmitted() int { return xsk.numTransmitted }

// FreeTxFrames returns how many transmit frames are idle in the transmit pool.
func (xsk *Socket) FreeTxFrames() int { return xsk.txPool.len() }

// SendBatch transmits up to len(payloads) packets, copying each into a transmit
// frame. It is the easy, high-level transmit call: it does all the ring
// bookkeeping for you — reclaiming completed frames, kicking the kernel, and
// never deadlocking when the ring is full — so you can just call it in a loop
// without touching Alloc/Transmit/Complete/Kick.
//
// It returns the number of packets actually queued this call, which may be
// fewer than len(payloads) (possibly zero) when the ring is momentarily full;
// queue the rest on a later call. Like the rest of the transmit side it is for
// a single transmit goroutine (or guard it with your own mutex).
//
// A payload longer than FrameSize cannot fit in a UMEM frame; SendBatch
// rejects the whole batch up front with an error rather than truncating it on
// the wire, and queues nothing.
func (xsk *Socket) SendBatch(payloads [][]byte) (int, error) {
	if xsk.multiBuffer() {
		// Multi-buffer socket: split oversized payloads across frames instead
		// of rejecting them.
		return xsk.sendBatchSG(payloads)
	}
	for i, p := range payloads {
		if len(p) > xsk.options.FrameSize {
			return 0, fmt.Errorf("afxdp: SendBatch payload %d is %d bytes, larger than FrameSize %d "+
				"(pass WithMultiBuffer to split packets across frames)",
				i, len(p), xsk.options.FrameSize)
		}
	}
	return xsk.SendFunc(len(payloads), func(i int, frame []byte) int {
		return copy(frame, payloads[i])
	})
}

// SendFunc is SendBatch without the intermediate copy: it transmits up to count
// packets, calling build to fill each frame in place (build writes into frame
// and returns the packet length). Use it when you want to construct packets
// directly in the UMEM or vary a field per packet (e.g. a packet generator). It
// handles the same ring bookkeeping as SendBatch and returns the number queued.
//
// build must return a length in [0, len(frame)]. Anything else is reported as
// an error and the whole batch is abandoned unqueued — the length would have
// described bytes that were never written to the frame.
func (xsk *Socket) SendFunc(count int, build func(i int, frame []byte) int) (int, error) {
	if !xsk.incref() {
		return 0, net.ErrClosed
	}
	defer xsk.decref()
	xsk.Complete(xsk.NumCompleted()) // reclaim already-sent frames
	free := xsk.NumFreeTxSlots()
	if free == 0 {
		// Ring full: kick so the kernel drains it (in copy mode it won't on its
		// own) and produces completions for the next call to reclaim.
		if xsk.kickNeeded() {
			_ = xsk.Kick()
		} else {
			xsk.statKicksSuppressed.Add(1)
		}
		return 0, nil
	}
	if count > free {
		count = free
	}
	descs := xsk.Alloc(count) // never more than free ring slots, so all transmit
	for i := range descs {
		frame := xsk.GetFrame(descs[i])
		n := build(i, frame)
		if n < 0 || n > len(frame) {
			// Nothing has been queued yet, so hand every allocated frame back
			// to the transmit pool before reporting the bad length.
			for _, d := range descs {
				xsk.txPool.push(xsk.frameBase(d.Addr))
			}
			return 0, fmt.Errorf("afxdp: SendFunc build returned length %d for packet %d, valid range is [0, %d]",
				n, i, len(frame))
		}
		descs[i].Len = uint32(n)
	}
	return xsk.Transmit(descs), nil
}

// Stats holds cumulative counters for a Socket. KernelStats carries the
// kernel's drop/error counters. It has a String method for easy logging.
type Stats struct {
	Filled      uint64 // fill descriptors consumed by the kernel
	Received    uint64 // frames received (consumed from the rx ring)
	Transmitted uint64 // frames sent (consumed by the kernel from the tx ring)
	Completed   uint64 // completions reaped via Complete; trails Transmitted if
	// you reap lazily, so prefer Transmitted for a "packets sent" count.
	Kicks           uint64 // tx kick syscalls issued (sendto), including drain retries
	KicksSuppressed uint64 // Transmit kicks skipped because need-wakeup showed the driver awake
	// Polls counts rx poll(2) syscalls — one per Poll call that actually
	// blocks. Divided by Received it gives packets per syscall, i.e. how well
	// your receive loop is batching: a healthy loaded queue reads in the
	// dozens or hundreds, while a value near 1 means you are paying a syscall
	// per packet and should drain more per wakeup.
	Polls uint64
	// RxKicks counts WakeupRx syscalls: explicit fill-ring wakeups issued by a
	// caller driving the rings directly instead of blocking in Poll.
	RxKicks     uint64
	KernelStats unix.XDPStatistics
}

// PacketsPerPoll returns how many frames were received per blocking poll(2) on
// average — the receive loop's batching efficiency. Higher is better: each
// syscall is amortized over that many packets. A value near 1 means a syscall
// per packet, usually because the loop drains less than what is waiting. It
// returns 0 before the first poll.
func (s Stats) PacketsPerPoll() float64 {
	if s.Polls == 0 {
		return 0
	}
	return float64(s.Received) / float64(s.Polls)
}

// String renders Stats as a single human-readable line.
func (s Stats) String() string {
	out := fmt.Sprintf("rx=%d tx=%d packets", s.Received, s.Transmitted)
	if s.Polls > 0 {
		out += fmt.Sprintf(", %.0f pkt/poll", s.PacketsPerPoll())
	}
	if drops := s.KernelStats.Rx_dropped + s.KernelStats.Rx_ring_full; drops > 0 {
		out += fmt.Sprintf(", rx_drops=%d", drops)
	}
	if inval := s.KernelStats.Rx_invalid_descs + s.KernelStats.Tx_invalid_descs; inval > 0 {
		out += fmt.Sprintf(", invalid_descs=%d", inval)
	}
	return out
}

// Stats returns ring counters plus the kernel's XDP_STATISTICS for this socket
// (which reports e.g. invalid descriptors and rx ring full drops).
//
// Stats may be called from a separate monitoring goroutine while the rx/tx
// loops run — a sample can be momentarily stale, but it never disturbs the
// data path (the data path takes no locks; only concurrent Stats callers
// serialize against each other). The kernel's ring indices are 32-bit, so the
// 64-bit counters here are maintained across wrap-arounds by sampling; call
// Stats at least once per 2^32 packets per socket (at 10G line rate on one
// queue that's every ~5 minutes — any periodic stats loop is plenty).
func (xsk *Socket) Stats() (Stats, error) {
	if !xsk.incref() {
		return Stats{}, net.ErrClosed
	}
	defer xsk.decref()
	var s Stats
	xsk.statsMu.Lock()
	s.Filled = xsk.statFilled.update(ldIdx(xsk.fillRing.Consumer))
	if xsk.rxRing.Consumer != nil {
		s.Received = xsk.statReceived.update(ldIdx(xsk.rxRing.Consumer))
	}
	if xsk.txRing.Consumer != nil {
		s.Transmitted = xsk.statTransmitted.update(ldIdx(xsk.txRing.Consumer))
	}
	if xsk.completionRing.Consumer != nil {
		s.Completed = xsk.statCompleted.update(ldIdx(xsk.completionRing.Consumer))
	}
	xsk.statsMu.Unlock()
	s.Kicks = xsk.statKicks.Load()
	s.KicksSuppressed = xsk.statKicksSuppressed.Load()
	s.Polls = xsk.statPolls.Load()
	s.RxKicks = xsk.statRxKicks.Load()
	size := uint64(unsafe.Sizeof(s.KernelStats))
	if rc, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_STATISTICS,
		uintptr(unsafe.Pointer(&s.KernelStats)), uintptr(unsafe.Pointer(&size)), 0); rc != 0 {
		return s, fmt.Errorf("afxdp: XDP_STATISTICS: %w", errno)
	}
	return s, nil
}

// ZeroCopy reports whether the kernel granted zero-copy mode on this socket.
// It reads XDP_OPTIONS, the authoritative source — bind flags only request a
// mode, they do not confirm it.
func (xsk *Socket) ZeroCopy() (bool, error) {
	if !xsk.incref() {
		return false, net.ErrClosed
	}
	defer xsk.decref()
	opt, err := unix.GetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_OPTIONS)
	if err != nil {
		return false, fmt.Errorf("afxdp: XDP_OPTIONS: %w", err)
	}
	return opt&unix.XDP_OPTIONS_ZEROCOPY != 0, nil
}

// Close releases the socket, its UMEM, and ring mappings. It is safe to call
// while another goroutine is blocked in Poll: that Poll is woken and returns
// net.ErrClosed, and Close waits for in-flight operations to finish before
// tearing down the memory they use. After Close, all methods are inert
// (Poll/Kick/Stats return net.ErrClosed; the rest return zero values) — but
// frame slices previously handed out by GetFrame must no longer be touched.
func (xsk *Socket) Close() error {
	if xsk.closing.Swap(true) {
		return nil // second Close: the first one did (or is doing) the work
	}
	// Wake any poller, then wait for every in-flight method call to drain
	// before invalidating the fds and mappings they might be using.
	if xsk.wakeFd != -1 {
		var one = [8]byte{1} // eventfd counter increment, little-endian 1
		_, _ = unix.Write(xsk.wakeFd, one[:])
	}
	for xsk.ops.Load() > 0 {
		time.Sleep(100 * time.Microsecond)
	}

	var firstErr error
	if xsk.fd != -1 {
		if err := unix.Close(xsk.fd); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("afxdp: close socket: %w", err)
		}
		xsk.fd = -1
	}
	if xsk.wakeFd != -1 {
		if err := unix.Close(xsk.wakeFd); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("afxdp: close eventfd: %w", err)
		}
		xsk.wakeFd = -1
	}
	// Drop every alias into the ring mappings before unmapping them.
	xsk.fillRing = umemRing{}
	xsk.completionRing = umemRing{}
	xsk.rxRing = rxTxRing{}
	xsk.txRing = rxTxRing{}
	for _, mem := range xsk.ringMems {
		if err := syscall.Munmap(mem); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("afxdp: munmap ring: %w", err)
		}
	}
	xsk.ringMems = nil
	if xsk.umem != nil {
		if err := syscall.Munmap(xsk.umem); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("afxdp: munmap UMEM: %w", err)
		}
		xsk.umem = nil
	}
	return firstErr
}

// PollWith parks like Poll but also wakes when any of the caller's extra
// descriptors becomes readable (a wake eventfd another goroutine signals,
// say), all in one syscall. It keeps the two safety properties of Poll that a
// hand-rolled poll over FD() silently loses: the socket fd is refcounted so a
// concurrent Close cannot recycle it mid-poll, and Close's wake descriptor is
// in the set so a closing socket never leaves the caller parked for the full
// timeout. Like Poll, it returns immediately when the fill ring is empty (the
// kernel cannot deliver without fill descriptors; refill and come back),
// except when the driver is parked awaiting an RX wakeup.
// Reports whether it was woken by readiness rather than the timeout.
func (xsk *Socket) PollWith(extra []int32, timeout time.Duration) (bool, error) {
	if !xsk.incref() {
		return false, net.ErrClosed
	}
	defer xsk.decref()
	// Same early-out as Poll: an empty fill ring means blocking is pointless —
	// unless the driver is parked waiting on us, where the poll(2) below is the
	// only thing that will restart it.
	if xsk.numFilled == 0 && !xsk.NeedsWakeupRx() {
		return true, nil
	}
	ms := -1
	if timeout >= 0 {
		ms = int(timeout / time.Millisecond)
		if ms == 0 && timeout > 0 {
			ms = 1 // don't turn a small positive timeout into "don't block"
		}
	}
	pfds := make([]unix.PollFd, 0, 2+len(extra))
	pfds = append(pfds,
		unix.PollFd{Fd: int32(xsk.fd), Events: unix.POLLIN},
		unix.PollFd{Fd: int32(xsk.wakeFd), Events: unix.POLLIN})
	for _, fd := range extra {
		pfds = append(pfds, unix.PollFd{Fd: fd, Events: unix.POLLIN})
	}
	var n int
	var err error
	xsk.statPolls.Add(1)
	for err = unix.EINTR; err == unix.EINTR; {
		n, err = unix.Poll(pfds, ms)
	}
	if err != nil {
		return false, err
	}
	if pfds[1].Revents != 0 { // woken by Close
		return false, net.ErrClosed
	}
	return n > 0, nil
}
