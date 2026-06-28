// Copyright 2024 Andree Toonk. All rights reserved.
// Portions Copyright 2019 Asavie Technologies Ltd.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import "golang.org/x/sys/unix"

// Options configures a Socket's UMEM and rings.
//
// The zero value is not valid; use DefaultOptions() and adjust, or rely on
// NewSocket / OpenFleet filling in defaults for any field left at zero.
//
// Frame budget. The UMEM holds NumFrames buffers of FrameSize bytes each.
// Those frames are split into two disjoint pools: TxFrames buffers are
// reserved for transmit, the remaining NumFrames-TxFrames for receive. The
// split is what lets one receive goroutine and one transmit goroutine run
// against the same Socket without locking or corrupting each other — they
// never touch the same frames (see the package doc).
type Options struct {
	// NumFrames is the total number of buffers in the UMEM (rx + tx).
	// Must be > 0. Default 4096.
	NumFrames int

	// FrameSize is the size in bytes of each UMEM buffer. Default 2048.
	//
	// For AF_XDP zero-copy on some drivers (notably AWS ENA) the frame size
	// must equal the page size, i.e. 4096. If zero-copy bind fails with
	// EINVAL and the kernel log says "Only page size chunks are supported",
	// set this to 4096.
	FrameSize int

	// TxFrames is how many of NumFrames are reserved for the transmit pool.
	// Must be < NumFrames. Default NumFrames/2. Set it lower if your workload
	// is receive-heavy (e.g. a pure sniffer can set TxFrames to a small value),
	// or higher for a transmit-heavy generator.
	TxFrames int

	// Ring sizes. Each must be a power of two. Defaults: 2048 for every ring.
	// FillRingNumDescs and RxRingNumDescs are the receive rings;
	// TxRingNumDescs and CompletionRingNumDescs are the transmit rings.
	// A ring set to zero disables that direction (you cannot disable both rx
	// and tx).
	FillRingNumDescs       int
	CompletionRingNumDescs int
	RxRingNumDescs         int
	TxRingNumDescs         int

	// BindFlags are passed to bind(2) in SockaddrXDP.Flags. Useful values:
	// unix.XDP_ZEROCOPY to demand zero-copy (bind fails if the driver can't),
	// unix.XDP_COPY to force copy mode, 0 to let the kernel choose. Default 0.
	BindFlags uint16

	// XDPFlags are passed when the BPF program is attached to the link.
	// Useful values: unix.XDP_FLAGS_DRV_MODE (native driver XDP),
	// unix.XDP_FLAGS_SKB_MODE (generic, works everywhere but slow),
	// unix.XDP_FLAGS_HW_MODE. Default 0 (kernel picks native, falls back to
	// generic). Used by Program.Attach and OpenFleet.
	XDPFlags uint32
}

// DefaultOptions returns Options with sane defaults for a balanced rx/tx
// workload: 4096 frames of 2048 bytes, split evenly, with 2048-entry rings.
func DefaultOptions() Options {
	return Options{
		NumFrames:              4096,
		FrameSize:              2048,
		TxFrames:               2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         2048,
		TxRingNumDescs:         2048,
		BindFlags:              0,
		XDPFlags:               0,
	}
}

// withDefaults returns a copy of o with any zero-valued field replaced by its
// default. A nil receiver yields DefaultOptions().
func (o *Options) withDefaults() Options {
	d := DefaultOptions()
	if o == nil {
		return d
	}
	out := *o
	if out.NumFrames == 0 {
		out.NumFrames = d.NumFrames
	}
	if out.FrameSize == 0 {
		out.FrameSize = d.FrameSize
	}
	if out.TxFrames == 0 {
		out.TxFrames = out.NumFrames / 2
	}
	if out.FillRingNumDescs == 0 {
		out.FillRingNumDescs = d.FillRingNumDescs
	}
	if out.CompletionRingNumDescs == 0 {
		out.CompletionRingNumDescs = d.CompletionRingNumDescs
	}
	if out.RxRingNumDescs == 0 {
		out.RxRingNumDescs = d.RxRingNumDescs
	}
	if out.TxRingNumDescs == 0 {
		out.TxRingNumDescs = d.TxRingNumDescs
	}
	return out
}

// Zero-copy / copy bind flag re-exports so callers don't have to import
// golang.org/x/sys/unix just for these.
const (
	BindZeroCopy = unix.XDP_ZEROCOPY
	BindCopy     = unix.XDP_COPY
)

// Option configures the high-level Open constructor using the functional
// options pattern. Compose them: afxdp.Open("eth0", afxdp.WithQueues(4),
// afxdp.WithUDPPorts(4789), afxdp.WithZeroCopy()).
type Option func(*config)

// config is the resolved configuration Open builds from the Options struct
// plus the fleet-level settings (queue count, packet filter, and XDP mode).
type config struct {
	opts    Options
	queues  int     // 0 means "all rx queues"
	matches []Match // packet filter; empty means "redirect all packets"
	mode    xdpMode // how to attach/bind; default modeAuto picks the best
}

// xdpMode selects how Open attaches the XDP program and binds the sockets.
// The default, modeAuto, tries the fastest working combination so callers
// don't have to reason about native vs generic or zero-copy vs copy.
type xdpMode int

const (
	// modeAuto tries native+zero-copy, then native+copy, then generic+copy,
	// using the first that the driver accepts. This is the default.
	modeAuto xdpMode = iota
	// modeNative forces native (driver) XDP; zero-copy if the driver supports
	// it, otherwise copy.
	modeNative
	// modeNativeZC requires native zero-copy; Open fails if it isn't available.
	modeNativeZC
	// modeGeneric forces generic (SKB) XDP with copy semantics. Slower, but
	// works anywhere — including veth and other virtual devices.
	modeGeneric
)

func newConfig(opts ...Option) config {
	// Start from a zero Options and let withDefaults (called by Open) fill any
	// field left unset. Crucially this means defaults are derived from the
	// final values — e.g. WithNumFrames(256) yields TxFrames=128, not the
	// fixed default of 2048 that would exceed it.
	var c config
	for _, o := range opts {
		o(&c)
	}
	return c
}

// WithQueues limits how many rx queues to bind, starting from queue 0. The
// default (or 0) binds every rx queue on the interface, which is usually what
// you want so no RSS-distributed traffic is missed.
func WithQueues(n int) Option { return func(c *config) { c.queues = n } }

// WithFilter installs an XDP packet filter built from one or more Matches. A
// packet is redirected to the AF_XDP sockets if it satisfies ANY match;
// everything else continues to the normal kernel stack. With no filter, every
// packet on the bound queues is redirected.
//
//	afxdp.Open("eth0", afxdp.WithFilter(
//		afxdp.MatchUDPPort(4789, 51820),
//		afxdp.MatchICMPEcho(),
//	))
//
// See Match for the available builders and their limitations.
func WithFilter(matches ...Match) Option {
	return func(c *config) { c.matches = append(c.matches, matches...) }
}

// WithUDPPorts is shorthand for WithFilter(MatchUDPPort(ports...)): redirect
// only IPv4/UDP packets to these destination ports, pass the rest to the
// kernel. For mixing protocols (e.g. UDP ports plus ICMP) use WithFilter.
func WithUDPPorts(ports ...uint16) Option {
	return func(c *config) { c.matches = append(c.matches, MatchUDPPort(ports...)) }
}

// WithNumFrames sets the total number of UMEM buffers (rx + tx). Default 4096.
func WithNumFrames(n int) Option { return func(c *config) { c.opts.NumFrames = n } }

// WithFrameSize sets the size of each UMEM buffer in bytes. Default 2048; use
// 4096 for zero-copy on drivers that require page-sized frames (e.g. AWS ENA).
func WithFrameSize(n int) Option { return func(c *config) { c.opts.FrameSize = n } }

// WithTxFrames sets how many of NumFrames are reserved for the transmit pool.
// Default half. Lower it for receive-heavy workloads, raise it for senders.
func WithTxFrames(n int) Option { return func(c *config) { c.opts.TxFrames = n } }

// WithRingSize sets all four ring sizes (fill, completion, rx, tx) at once.
// Must be a power of two. Default 2048. Use WithOptions for per-ring control.
func WithRingSize(n int) Option {
	return func(c *config) {
		c.opts.FillRingNumDescs = n
		c.opts.CompletionRingNumDescs = n
		c.opts.RxRingNumDescs = n
		c.opts.TxRingNumDescs = n
	}
}

// By default Open auto-selects the XDP mode (native zero-copy, falling back to
// native copy, then generic copy). The options below override that only when
// you have a specific need; most callers should not set any of them.

// WithZeroCopy requires native zero-copy mode: Open fails if the driver can't
// provide it. Use this when you must know you're getting the fast path.
func WithZeroCopy() Option { return func(c *config) { c.mode = modeNativeZC } }

// WithDriverMode forces native (driver) XDP, using zero-copy when the driver
// supports it and copy otherwise. Native XDP reinitializes the driver's queues,
// which briefly blips the link on attach and detach.
func WithDriverMode() Option { return func(c *config) { c.mode = modeNative } }

// WithGenericMode forces generic (SKB) XDP with copy semantics. It is slower
// and never zero-copy, but works on any interface — including veth and other
// virtual devices that have no native XDP — and does not blip the link.
func WithGenericMode() Option { return func(c *config) { c.mode = modeGeneric } }

// WithOptions replaces the whole Options struct, for full manual control. Apply
// it before other With* options, which then override individual fields.
func WithOptions(o Options) Option { return func(c *config) { c.opts = o } }
