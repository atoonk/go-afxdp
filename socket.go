//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Portions Copyright 2019 Asavie Technologies Ltd.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
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

type umemRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []uint64
}

type rxTxRing struct {
	Producer *uint32
	Consumer *uint32
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
type Socket struct {
	fd      int
	ifindex int
	options Options
	umem    []byte

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

	// Transmit-side state, owned by the transmit goroutine.
	txPool         *framePool
	txScratch      []Desc
	txPopScratch   []uint64
	numTransmitted int

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

	xsk := &Socket{fd: -1, ifindex: ifindex, options: opts}

	var err error
	xsk.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("afxdp: AF_XDP socket: %w", err)
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
		xsk.txRing.Descs = unsafe.Slice((*Desc)(unsafe.Add(base, offsets.Tx.Desc)), opts.TxRingNumDescs)
		xsk.txScratch = make([]Desc, 0, opts.TxRingNumDescs)
	}

	sa := &unix.SockaddrXDP{
		Flags:   opts.BindFlags,
		Ifindex: uint32(ifindex),
		QueueID: uint32(queueID),
	}
	if err = unix.Bind(xsk.fd, sa); err != nil {
		xsk.Close()
		return nil, fmt.Errorf("afxdp: bind queue %d: %w", queueID, err)
	}

	// Split the UMEM frames into disjoint receive and transmit pools.
	// Receive frames come first: [0, rxFrames). Transmit frames follow:
	// [rxFrames, NumFrames).
	rxFrames := opts.NumFrames - opts.TxFrames
	xsk.rxPool = newFramePool(0, rxFrames, opts.FrameSize)
	xsk.txPool = newFramePool(rxFrames, opts.TxFrames, opts.FrameSize)
	xsk.popScratch = make([]uint64, 0, opts.FillRingNumDescs)

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

func (xsk *Socket) frameBase(addr uint64) uint64 {
	return addr - (addr % uint64(xsk.options.FrameSize))
}

// ---------------- Receive side (one receive goroutine) ----------------

// Fill moves up to n free receive frames onto the fill ring, where the kernel
// will write incoming packets into them. It returns the number of frames
// submitted, which may be less than n if the receive pool or the fill ring is
// short on space. Call it before Poll so the kernel always has buffers.
func (xsk *Socket) Fill(n int) int {
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

// Poll blocks until the kernel has received frames (or the timeout, in
// milliseconds, elapses; negative means wait forever). It returns the number
// of received frames now available to Receive. Poll only watches the receive
// direction; the transmit side drives completions via Complete/Kick.
func (xsk *Socket) Poll(timeoutMs int) (numReceived int, err error) {
	if xsk.numFilled == 0 {
		return 0, nil
	}
	pfds := [1]unix.PollFd{{Fd: int32(xsk.fd), Events: unix.POLLIN}}
	for err = unix.EINTR; err == unix.EINTR; {
		_, err = unix.Poll(pfds[:], timeoutMs)
	}
	if err != nil {
		return 0, err
	}
	return xsk.NumReceived(), nil
}

// Receive consumes up to max received descriptors from the rx ring. The
// returned slice is owned by the Socket and reused on the next Receive call;
// copy out anything you need to keep. After you are done reading the frames,
// return them with Recycle so they can be filled again.
func (xsk *Socket) Receive(max int) []Desc {
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
	_ = xsk.Kick()
	return len(descs)
}

// Kick asks the kernel to process the tx ring. Transmit calls it for you after
// queueing frames, so you normally don't call it directly — with one important
// exception: if the tx ring fills up (NumFreeTxSlots returns 0) so you can't
// Transmit more, call Kick anyway to keep the kernel draining the ring and
// producing completions. In copy mode the kernel will not drain the ring
// without a kick, so a tight "if full, continue" loop that skips the kick
// deadlocks. (In zero-copy the driver drains on its own, but kicking is
// harmless.)
func (xsk *Socket) Kick() error {
	for {
		rc, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(xsk.fd),
			0, 0, uintptr(unix.MSG_DONTWAIT), 0, 0)
		if rc == 0 {
			return nil
		}
		switch errno {
		case unix.EINTR:
			continue
		case unix.EAGAIN, unix.EBUSY:
			// EAGAIN: kernel busy, will pick up the ring later.
			// EBUSY: completed but not yet sent. Both are non-fatal.
			return nil
		default:
			return fmt.Errorf("afxdp: sendto kick: %w", errno)
		}
	}
}

// Complete reclaims up to n transmitted frames from the completion ring and
// returns them to the transmit pool, making them available to Alloc again.
// It returns how many frames were reclaimed.
func (xsk *Socket) Complete(n int) int {
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
func (xsk *Socket) SendBatch(payloads [][]byte) int {
	return xsk.SendFunc(len(payloads), func(i int, frame []byte) int {
		return copy(frame, payloads[i])
	})
}

// SendFunc is SendBatch without the intermediate copy: it transmits up to count
// packets, calling build to fill each frame in place (build writes into frame
// and returns the packet length). Use it when you want to construct packets
// directly in the UMEM or vary a field per packet (e.g. a packet generator). It
// handles the same ring bookkeeping as SendBatch and returns the number queued.
func (xsk *Socket) SendFunc(count int, build func(i int, frame []byte) int) int {
	xsk.Complete(xsk.NumCompleted()) // reclaim already-sent frames
	free := xsk.NumFreeTxSlots()
	if free == 0 {
		// Ring full: kick so the kernel drains it (in copy mode it won't on its
		// own) and produces completions for the next call to reclaim.
		_ = xsk.Kick()
		return 0
	}
	if count > free {
		count = free
	}
	descs := xsk.Alloc(count) // never more than free ring slots, so all transmit
	for i := range descs {
		descs[i].Len = uint32(build(i, xsk.GetFrame(descs[i])))
	}
	return xsk.Transmit(descs)
}

// Stats holds cumulative counters for a Socket. KernelStats carries the
// kernel's drop/error counters. It has a String method for easy logging.
type Stats struct {
	Filled      uint64 // fill descriptors consumed by the kernel
	Received    uint64 // frames received (consumed from the rx ring)
	Transmitted uint64 // frames sent (consumed by the kernel from the tx ring)
	Completed   uint64 // completions reaped via Complete; trails Transmitted if
	// you reap lazily, so prefer Transmitted for a "packets sent" count.
	KernelStats unix.XDPStatistics
}

// String renders Stats as a single human-readable line.
func (s Stats) String() string {
	out := fmt.Sprintf("rx=%d tx=%d packets", s.Received, s.Transmitted)
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
	opt, err := unix.GetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_OPTIONS)
	if err != nil {
		return false, fmt.Errorf("afxdp: XDP_OPTIONS: %w", err)
	}
	return opt&unix.XDP_OPTIONS_ZEROCOPY != 0, nil
}

// Close releases the socket, its UMEM, and ring mappings.
func (xsk *Socket) Close() error {
	var firstErr error
	if xsk.fd != -1 {
		if err := unix.Close(xsk.fd); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("afxdp: close socket: %w", err)
		}
		xsk.fd = -1
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
