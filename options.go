//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Portions Copyright 2019 Asavie Technologies Ltd.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"time"

	"golang.org/x/sys/unix"
)

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
	// Must be > 0. Default 8192.
	NumFrames int

	// FrameSize is the size in bytes of each UMEM buffer. Default 2048.
	//
	// For AF_XDP zero-copy on some drivers the frame size must equal the page
	// size, i.e. 4096; with a smaller frame the bind silently falls back to
	// copy mode. Open detects this for AWS ENA and defaults FrameSize to 4096
	// there automatically (unless you set it or force generic mode). On any
	// other driver whose zero-copy bind needs page-sized chunks, set 4096 here.
	FrameSize int

	// TxFrames is how many of NumFrames are reserved for the transmit pool.
	// Must be < NumFrames. Default NumFrames/2. Set it lower if your workload
	// is receive-heavy (e.g. a pure sniffer can set TxFrames to a small value),
	// or higher for a transmit-heavy generator.
	TxFrames int

	// Ring sizes. Each must be a power of two. Defaults: 4096 for every ring.
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

	// TxReuseRxFrames routes completions by address region (rx frames back to the
	// rx pool) so received frames can be transmitted in place. Requires a
	// single goroutine driving both sides of the socket; see WithTxReuseRxFrames.
	TxReuseRxFrames bool

	// BusyPollUsecs/BusyPollBudget enable XSK preferred busy polling
	// (SO_PREFER_BUSY_POLL, kernel 5.11+): the application's own poll and
	// recvfrom syscalls drive NAPI directly with up to BusyPollBudget
	// descriptors per call, decoupling RX descriptor posting from the
	// interrupt rate. Without it a driver posts XSK descriptors only during
	// interrupt-clocked NAPI cycles (budget 64), which caps per-queue
	// delivery at 64 x the moderated interrupt rate no matter how fast
	// userspace drains (measured: exactly 128k pps/queue on mlx5).
	// Effective only alongside the per-device sysctls napi_defer_hard_irqs
	// and gro_flush_timeout. Zero values leave busy polling off.
	BusyPollUsecs  int
	BusyPollBudget int

	// XDPFlags are passed when the BPF program is attached to the link.
	// Useful values: unix.XDP_FLAGS_DRV_MODE (native driver XDP),
	// unix.XDP_FLAGS_SKB_MODE (generic, works everywhere but slow),
	// unix.XDP_FLAGS_HW_MODE. Default 0 (kernel picks native, falls back to
	// generic). Used by Program.Attach and OpenFleet.
	XDPFlags uint32
}

// DefaultOptions returns Options with sane defaults for a balanced rx/tx
// workload: 8192 frames of 2048 bytes, split evenly, with 4096-entry rings.
//
// The ring depth matters for line-rate receive: a shallow rx/fill ring
// overflows between drains (visible as XDP_STATISTICS rx_ring_full) and caps
// throughput well below what the NIC can deliver. 4096-entry rings backed by a
// large enough frame pool keep the driver fed at 10G+ small-packet rates; the
// ring memory this costs is negligible next to the UMEM. A pure receiver can
// hand almost all frames to the rx pool with WithReceiveHeavy.
func DefaultOptions() Options {
	return Options{
		NumFrames:              8192,
		FrameSize:              2048,
		TxFrames:               4096,
		FillRingNumDescs:       4096,
		CompletionRingNumDescs: 4096,
		RxRingNumDescs:         4096,
		TxRingNumDescs:         4096,
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

	keepManagement bool     // pass management traffic to the kernel (see WithKeepManagement)
	mgmtTCPPorts   []uint16 // TCP ports treated as management; defaults to 22

	multiBuffer bool // load the XDP program with BPF_F_XDP_HAS_FRAGS (see WithMultiBuffer)

	// NAPI auto-tuning (see WithoutAutoTune). noAutoTune disables it; the two
	// values are zero unless WithNAPITuning overrode them.
	noAutoTune    bool
	napiDeferIRQs int
	napiFlush     time.Duration
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
	// fixed default of 4096 that would exceed it.
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

// WithNumFrames sets the total number of UMEM buffers (rx + tx). Default 8192.
func WithNumFrames(n int) Option { return func(c *config) { c.opts.NumFrames = n } }

// WithFrameSize sets the size of each UMEM buffer in bytes. Default 2048; use
// 4096 for zero-copy on drivers that require page-sized frames. On AWS ENA Open
// already defaults to 4096, so you only need this to override that or to handle
// another such driver.
func WithFrameSize(n int) Option { return func(c *config) { c.opts.FrameSize = n } }

// WithTxFrames sets how many of NumFrames are reserved for the transmit pool.
// Default half. Lower it for receive-heavy workloads, raise it for senders.
func WithTxFrames(n int) Option { return func(c *config) { c.opts.TxFrames = n } }

// WithReceiveHeavy is an optional optimization for receive-only sockets (sinks,
// sniffers, taps that never transmit). The default splits the UMEM evenly
// between rx and tx pools; a pure receiver never uses the tx half, so this
// reserves just 64 tx frames and hands the rest to rx. That is not required to
// reach line rate — the default rings already do — but it gives the fill ring
// generous slack (the rx pool ends up far larger than the fill ring) so the
// driver never starves under bursts, and reclaims the otherwise-idle tx memory.
// Don't use it on a socket that also transmits.
func WithReceiveHeavy() Option { return func(c *config) { c.opts.TxFrames = 64 } }

// WithRingSize sets all four ring sizes (fill, completion, rx, tx) at once.
// Must be a power of two. Default 4096. Use WithOptions for per-ring control.
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

// WithNeedWakeup binds with XDP_USE_NEED_WAKEUP, letting the driver stop polling
// when it has no receive buffers (or nothing to transmit) and wait to be woken.
//
// Turn this on. Without it the driver cannot tell us it is starved, so instead of
// sleeping it reports work==budget on every NAPI poll, napi_complete is never
// reached, and ksoftirqd re-polls the queue in a tight loop. Measured on an
// ixgbe 10G NIC with 8 queues: 25 million NAPI polls per second and 65% of a
// 12-core box consumed in softirq while forwarding ZERO packets. The waking is
// handled for you — Poll wakes the receive side, Kick the transmit side.
//
// It is not the default only because it changes the kernel contract for callers
// that drive the rings themselves rather than through Poll/Kick.
func WithNeedWakeup() Option {
	return func(c *config) { c.opts.BindFlags |= unix.XDP_USE_NEED_WAKEUP }
}

// WithTxReuseRxFrames allows transmitting RECEIVE-pool frames in place: Complete
// routes each completed frame back to the pool its address belongs to (rx
// region or tx region) instead of pushing everything to the transmit pool.
// That makes forward-in-place legal: Receive a frame, rewrite it, Transmit
// the same descriptor, and on completion the frame returns to the receive
// pool for the fill ring — no copy, no pool imbalance.
//
// It changes the concurrency contract: without it, the rx pool is touched
// only by the receive side and the tx pool only by the transmit side (the
// lock-free 1RX+1TX split). With it, Complete — which runs on the transmit
// side — may push to the rx pool. Use it only when ONE goroutine drives both
// sides of the socket (the router/forwarder shape).
func WithTxReuseRxFrames() Option {
	return func(c *config) { c.opts.TxReuseRxFrames = true }
}

// WithBusyPoll enables XSK preferred busy polling (see
// SocketOptions.BusyPollUsecs). usecs is the SO_BUSY_POLL duration, budget the
// per-syscall descriptor budget (the kernel caps it at 512; 256 is a sensible
// start). Pair with WithNeedWakeup: the need-wakeup flag is what tells the
// caller its next syscall must drive NAPI.
func WithBusyPoll(usecs, budget int) Option {
	return func(c *config) { c.opts.BusyPollUsecs = usecs; c.opts.BusyPollBudget = budget }
}

// WithMultiBuffer enables multi-buffer (scatter-gather) mode, which lets a
// packet span several UMEM frames instead of being limited to one. It is what
// makes jumbo frames work: at the default 4096-byte frame size a 9001-byte
// packet arrives as three chained descriptors.
//
// Two things change. The XDP program is loaded with BPF_F_XDP_HAS_FRAGS, which
// is also what lets it attach at all on drivers that otherwise cap the MTU for
// XDP (AWS ENA refuses a native attach above 3502 bytes without it). And the
// socket binds with XDP_USE_SG, without which the kernel silently drops every
// multi-buffer packet.
//
// Use ReceivePackets rather than Receive to read chained packets: Receive
// returns one Desc per *frame*, so a jumbo packet looks like several unrelated
// descriptors. SendBatch splits oversized payloads across frames for you.
//
// The cost is zero-copy. A device reports its multi-buffer zero-copy limit as
// xdp-zc-max-segs; where that is 1 (AWS ENA today) the kernel refuses an
// XDP_USE_SG bind in zero-copy mode, so Open settles for native copy mode.
// Check Info().ZeroCopy if that matters to you — on such a NIC, lowering the
// MTU and leaving this option off is faster than turning it on.
func WithMultiBuffer() Option {
	return func(c *config) {
		c.multiBuffer = true
		c.opts.BindFlags |= unix.XDP_USE_SG
	}
}

// WithKeepManagement keeps the traffic that keeps you logged in out of the
// capture, so you can point a broad filter — MatchAll() in particular — at the
// same NIC you are administering the box through without cutting yourself off:
//
//	afxdp.Open("eth0",
//		afxdp.WithFilter(afxdp.MatchAll()), // capture everything...
//		afxdp.WithKeepManagement(),         // ...except what keeps me logged in
//	)
//
// These are passed to the kernel instead of being redirected:
//
//   - ARP, and IPv6 neighbour discovery (ICMPv6 types 133-137)
//   - TCP to and from port 22 (plus any extraTCPPorts), addressed to this
//     interface
//   - DNS replies: UDP and TCP with source port 53, addressed to this interface
//
// ARP and ND matter more than the SSH rule does. Without them the kernel cannot
// refresh the gateway's link-layer address, and roughly a minute later the box
// is unreachable however carefully its SSH packets were passed through.
//
// The port rules are scoped to the addresses the interface has when Open is
// called, so a router still captures transit traffic on port 22 — only traffic
// addressed to this box is spared. Addresses added afterwards are not covered;
// reopen the fleet if they change. If the addresses cannot be determined the
// rules fall back to matching any destination, which captures less but will not
// strand you.
//
// Pass extraTCPPorts for SSH on a non-standard port, or another admin service
// you need to survive: WithKeepManagement(2222).
//
// Two caveats worth knowing. Traffic *from* port 22 or 53 to this host is not
// captured, so a sender that picks those source ports can dodge the capture —
// irrelevant for measurement, relevant if you are hunting an adversary. And if
// you administer the box through a different NIC than the one you are capturing
// on, you do not need this at all.
func WithKeepManagement(extraTCPPorts ...uint16) Option {
	return func(c *config) {
		c.keepManagement = true
		c.mgmtTCPPorts = append([]uint16{22}, extraTCPPorts...)
	}
}

// WithoutAutoTune leaves the interface's NAPI settings exactly as it found them.
//
// By default Open defers NAPI on a native-mode NIC (napi_defer_hard_irqs and
// gro_flush_timeout under /sys/class/net/<iface>/) so the kernel batches packets
// instead of waking the receiver thousands of times a second. On a 100G Mellanox
// sink that took the receiver from 36.5 to 24.2 of 48 cores for the same
// 118.8 Mpps — the single biggest tuning win we measured, and the sort of thing
// this library is meant to get right for you rather than leave in a README.
//
// The settings are restored when the Fleet is closed, and Fleet.Info reports
// what was applied. They are properties of the interface rather than of this
// process, though, so use this option if you would rather manage them yourself,
// if something else on the box owns that interface's tuning, or if you need the
// lowest possible latency at low packet rates (deferring can hold a packet for
// up to the flush timeout when traffic is sparse). Generic/SKB mode is never
// tuned, so veth and test setups are untouched either way.
func WithoutAutoTune() Option { return func(c *config) { c.noAutoTune = true } }

// WithNAPITuning overrides the auto-tuning values. deferIRQs sets
// napi_defer_hard_irqs and flush sets gro_flush_timeout; the defaults are 2 and
// 200µs. Raising them further batches harder but risks the NIC dropping because
// NAPI stops running often enough — at 10 and 500µs our 100G sink fell from
// 118.8 to 77 Mpps with 29M discards a second. See WithoutAutoTune.
func WithNAPITuning(deferIRQs int, flush time.Duration) Option {
	return func(c *config) {
		c.napiDeferIRQs = deferIRQs
		c.napiFlush = flush
	}
}

// WithOptions replaces the whole Options struct, for full manual control. Apply
// it before other With* options, which then override individual fields.
func WithOptions(o Options) Option { return func(c *config) { c.opts = o } }
