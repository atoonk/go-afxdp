//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Fleet is a set of AF_XDP sockets (XSKs) — one per rx queue on an interface —
// bound together under a single XDP program. ("Fleet" is this library's term,
// not standard AF_XDP vocabulary; the standard names stop at the single socket,
// the XSK.)
//
// It is the easy path: most NICs spread incoming traffic across several rx
// queues (RSS), and a socket bound to only queue 0 sees just its share. A Fleet
// binds every queue so you receive all of the traffic, and gives you N
// independent sockets to drive from N goroutines.
//
// Each socket follows the per-Socket concurrency rule: one receive goroutine
// and one transmit goroutine per socket, lock-free. A common pattern is one
// goroutine per queue handling both directions for that queue.
type Fleet struct {
	iface   string
	ifindex int
	opts    Options
	filter  string // human-readable summary of the applied XDP filter
	program *Program
	sockets []*Socket
}

// openFleets pins every Fleet returned by Open until Close is called.
//
// This is load-bearing, not bookkeeping: the XDP program is held by a BPF link
// whose file descriptor is owned by cilium/ebpf objects inside the Fleet, and
// cilium/ebpf closes those fds from a GC finalizer. A typical application only
// keeps the per-queue *Sockets after startup (see examples/drop), so without
// this pin the garbage collector eventually collects the unreachable Fleet,
// the finalizer closes the link fd, and the kernel silently DETACHES the XDP
// program — sockets stay bound but receive nothing, with no error anywhere.
// Pinning here means a Fleet lives until Close() or process exit, which is the
// only sane lifetime for an attached XDP program.
var (
	openFleetsMu sync.Mutex
	openFleets   = make(map[*Fleet]struct{})
)

// CountQueues returns the number of rx queues on an interface, i.e. the number
// of AF_XDP sockets needed to receive all RSS-distributed traffic. It reads
// /sys/class/net/<iface>/queues, which reflects the live real_num_rx_queues.
func CountQueues(iface string) (int, error) {
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", iface, "queues"))
	if err != nil {
		return 0, fmt.Errorf("afxdp: count queues for %s: %w", iface, err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("afxdp: no rx queues found for %s", iface)
	}
	return n, nil
}

// Open is the easy, high-level constructor. It attaches an XDP program to an
// interface, binds one AF_XDP socket per rx queue, and registers each so the
// traffic you asked for is delivered. Configure it with functional options:
//
//	fleet, err := afxdp.Open("eth0",
//		afxdp.WithUDPPorts(4789),   // only UDP/4789 to us, rest to the kernel
//		afxdp.WithQueues(4),        // bind 4 queues (default: all)
//
// A filter is REQUIRED: Open returns an error if you don't pass one. Without a
// filter every packet on the interface would be redirected to your sockets and
// kept from the kernel — an easy way to cut off your own SSH. Pass WithUDPPorts
// / WithFilter to capture specific traffic, WithFilter(MatchAll()) to take
// everything on purpose, or WithFilter(MatchNone()) for transmit-only.
//
// Open auto-selects the XDP mode: it tries native zero-copy, then native copy,
// then generic copy, using the first the driver accepts. You don't have to
// reason about modes; check Fleet.Info to see which was chosen. Override with
// WithDriverMode, WithGenericMode, or WithZeroCopy only if you have a need.
//
// On any error it cleans up whatever it already created. Each socket gets its
// own UMEM of NumFrames*FrameSize bytes, so total memory scales with the queue
// count — size NumFrames (WithNumFrames) accordingly on many-queue NICs.
func Open(iface string, opts ...Option) (*Fleet, error) {
	cfg := newConfig(opts...)
	base := cfg.opts.withDefaults()

	// AWS ENA's zero-copy datapath requires page-sized (4096-byte) UMEM frames;
	// with the default 2048 the bind silently falls back to native *copy* mode.
	// When the caller hasn't chosen a frame size and native/zero-copy is still on
	// the table, default to 4096 on ena so zero-copy works out of the box. Skipped
	// for forced generic mode (zero-copy is impossible there, so the bigger frames
	// would only waste UMEM); an explicit WithFrameSize always wins.
	if cfg.opts.FrameSize == 0 && cfg.mode != modeGeneric && interfaceDriver(iface) == "ena" {
		base.FrameSize = 4096
	}

	if len(cfg.matches) == 0 {
		return nil, fmt.Errorf("afxdp: Open(%q) needs a filter — without one every packet "+
			"on the interface would be redirected to your sockets and kept from the kernel "+
			"(cutting off SSH and everything else). Pass WithUDPPorts(...) or WithFilter(...) "+
			"to capture specific traffic, WithFilter(MatchAll()) to take everything on purpose, "+
			"or WithFilter(MatchNone()) for transmit-only", iface)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("afxdp: look up %s: %w", iface, err)
	}
	ifindex := link.Attrs().Index

	total, err := CountQueues(iface)
	if err != nil {
		return nil, err
	}
	nQueues := total
	if cfg.queues > 0 && cfg.queues < total {
		nQueues = cfg.queues
	}

	filter := filterDesc(cfg.matches)

	// Even a transmit-only Fleet (MatchNone) needs its XDP program attached:
	// in principle AF_XDP TX doesn't require one, but in practice drivers only
	// activate the XSK TX datapath alongside an attached program (ixgbe
	// allocates its XDP TX rings only then; ENA accepts a program-less
	// zero-copy bind and then silently never services the TX ring — verified
	// 2026-07: bind succeeds, completions stall after one burst, nothing hits
	// the wire). So there is no attach-free fast path to try first.

	// Try each attach mode in preference order. For a given attach mode we
	// attach the program once (native attach blips the link), then try its
	// bind variants (zero-copy before copy) without re-attaching.
	var lastErr error
	for _, g := range modeGroups(cfg.mode) {
		prog, err := buildProgram(nQueues, cfg.matches)
		if err != nil {
			return nil, err // program build failure isn't mode-related
		}
		if err := prog.Attach(ifindex, g.xdpFlags); err != nil {
			prog.Close()
			lastErr = fmt.Errorf("%s attach: %w", g.label, err)
			continue
		}
		for _, bindFlags := range g.bindFlags {
			opts := base
			opts.BindFlags = bindFlags
			opts.XDPFlags = g.xdpFlags
			socks, err := registerSockets(prog, ifindex, nQueues, &opts)
			if err != nil {
				lastErr = fmt.Errorf("%s bind: %w", g.label, err)
				continue
			}
			f := &Fleet{iface: iface, ifindex: ifindex, opts: opts, filter: filter, program: prog, sockets: socks}
			openFleetsMu.Lock()
			openFleets[f] = struct{}{}
			openFleetsMu.Unlock()
			return f, nil
		}
		prog.Detach(ifindex)
		prog.Close()
	}
	return nil, fmt.Errorf("afxdp: could not open %s (%d queues): %w", iface, nQueues, lastErr)
}

// modeGroup is one attach mode and the bind variants to try under it.
type modeGroup struct {
	xdpFlags  uint32
	bindFlags []uint16
	label     string
}

// modeGroups returns the attach/bind attempts for a mode, in preference order.
func modeGroups(m xdpMode) []modeGroup {
	native := func(binds ...uint16) modeGroup {
		return modeGroup{unix.XDP_FLAGS_DRV_MODE, binds, "native"}
	}
	generic := modeGroup{unix.XDP_FLAGS_SKB_MODE, []uint16{unix.XDP_COPY}, "generic"}
	switch m {
	case modeGeneric:
		return []modeGroup{generic}
	case modeNativeZC:
		return []modeGroup{native(unix.XDP_ZEROCOPY)}
	case modeNative:
		return []modeGroup{native(unix.XDP_ZEROCOPY, unix.XDP_COPY)}
	default: // modeAuto
		return []modeGroup{native(unix.XDP_ZEROCOPY, unix.XDP_COPY), generic}
	}
}

// buildProgram makes the redirect-all or filtered XDP program for nQueues.
func buildProgram(nQueues int, matches []Match) (*Program, error) {
	if len(matches) > 0 {
		return newFilterProgram(nQueues, matches)
	}
	return NewProgram(nQueues)
}

// registerSockets opens and registers one socket per queue against an
// already-attached program. On any failure it closes whatever it opened (but
// leaves the program attached, so the caller can retry with other bind flags).
func registerSockets(prog *Program, ifindex, nQueues int, opts *Options) ([]*Socket, error) {
	var socks []*Socket
	for q := 0; q < nQueues; q++ {
		xsk, err := NewSocket(ifindex, q, opts)
		if err != nil {
			closeAll(socks)
			return nil, fmt.Errorf("queue %d: %w", q, err)
		}
		if err := prog.Register(q, xsk.FD()); err != nil {
			xsk.Close()
			closeAll(socks)
			return nil, err
		}
		socks = append(socks, xsk)
	}
	return socks, nil
}

func closeAll(socks []*Socket) {
	for _, s := range socks {
		s.Close()
	}
}

// OpenFleet is a thin wrapper around Open for callers that already hold an
// Options struct. Prefer Open with functional options.
//
// Deprecated: use Open(iface, afxdp.WithOptions(opts)).
func OpenFleet(iface string, options *Options) (*Fleet, error) {
	if options == nil {
		return Open(iface)
	}
	return Open(iface, WithOptions(*options))
}

// WaitLinkUp blocks until the Fleet's interface is operationally up, or the
// timeout elapses; it reports whether the link is up.
//
// Attaching a native XDP program makes many drivers (ixgbe, for one)
// reinitialize their rings, which bounces the physical link for several
// seconds while it renegotiates. Until carrier returns nothing is received
// and anything transmitted is lost, so call this after Open — on senders and
// receivers alike — before starting traffic or judging counters. The link
// must hold up for about a second of consecutive readings before this
// returns: the attach-induced flap can begin a moment after Open returns, so
// a single instantaneous "up" could race it.
func (f *Fleet) WaitLinkUp(timeout time.Duration) bool {
	const stable = 5 // consecutive 200ms "up" readings required
	up := 0
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		l, err := netlink.LinkByIndex(f.ifindex)
		if err == nil && l.Attrs().OperState == netlink.OperUp {
			if up++; up >= stable {
				return true
			}
		} else {
			up = 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// Sockets returns the per-queue sockets, indexed by queue ID.
func (f *Fleet) Sockets() []*Socket { return f.sockets }

// Socket returns the socket bound to a specific queue ID.
func (f *Fleet) Socket(queueID int) *Socket {
	if queueID < 0 || queueID >= len(f.sockets) {
		return nil
	}
	return f.sockets[queueID]
}

// NumQueues returns how many queues (and sockets) the Fleet manages.
func (f *Fleet) NumQueues() int { return len(f.sockets) }

// Program returns the underlying XDP program, e.g. to register or unregister
// queues manually.
func (f *Fleet) Program() *Program { return f.program }

// Close unregisters and closes every socket, detaches the XDP program, and
// releases its maps. It returns the first error encountered but always
// attempts every step.
func (f *Fleet) Close() error {
	openFleetsMu.Lock()
	delete(openFleets, f)
	openFleetsMu.Unlock()
	var firstErr error
	for q, xsk := range f.sockets {
		if f.program != nil {
			if err := f.program.Unregister(q); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := xsk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	f.sockets = nil
	if f.program != nil {
		if err := f.program.Detach(f.ifindex); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := f.program.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		f.program = nil
	}
	return firstErr
}
