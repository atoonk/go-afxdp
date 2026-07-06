// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
Package afxdp is a small, easy-to-use Go library for AF_XDP sockets.

AF_XDP delivers packets from a network driver straight into a userspace
process, bypassing the kernel network stack, for very high packet rates. See
https://www.kernel.org/doc/html/latest/networking/af_xdp.html for background.

# Terminology

AF_XDP has its own vocabulary. An XSK ("XDP socket") is a single AF_XDP socket
bound to one NIC receive queue; xsk is the conventional variable name for one,
and here it is the Socket type. A UMEM is the memory region shared with the
kernel that holds packet buffers (frames). Four single-producer/single-consumer
rings move frames to and from the kernel: fill and rx on the receive side, tx
and completion on the transmit side. A Fleet (this library's term, not standard
AF_XDP) is one XSK per receive queue bound together under a single XDP program.

This package is a fork of github.com/asavie/xdp. It keeps that project's proven
UMEM and ring setup but changes two things that matter in production:

  - Independent rx/tx frame pools. The UMEM frames are split into a disjoint
    receive pool and transmit pool, each owned by a single direction. One
    receive goroutine and one transmit goroutine can therefore run against the
    same Socket with no lock and no shared mutable state. The upstream library
    shared one free-frame list across both directions, so a concurrent fill and
    transmit could hand out the same frame and corrupt packets on the wire —
    silent, because the corruption only shows up as dropped frames at the peer.

  - All queues, easily. Real NICs spread received traffic across several rx
    queues. OpenFleet binds one socket to every queue under a single XDP
    program, so you get all the traffic and N sockets to drive in parallel,
    without wiring up per-queue maps by hand.

# Concurrency

A Socket is safe for one receive goroutine concurrent with one transmit
goroutine, lock-free. Within a direction it is single-threaded: if you transmit
from multiple goroutines, serialize the transmit calls (Alloc/Transmit/Complete)
yourself, or give each producer its own queue via a Fleet. The receive side is
likewise single-consumer.

# Receiving

Post buffers, wait, read them, recycle them:

	for {
		xsk.Fill(xsk.NumFreeFillSlots()) // give the kernel buffers
		n, err := xsk.Poll(-1)           // block until packets arrive
		if err != nil {
			log.Fatal(err)
		}
		descs := xsk.Receive(n)
		for _, d := range descs {
			frame := xsk.GetFrame(d) // the received bytes
			_ = frame
		}
		xsk.Recycle(descs) // return frames so they can be filled again
	}

# Transmitting

The easy way is SendBatch (or SendFunc), which does all the ring bookkeeping for
you — reclaiming sent frames, kicking the kernel, and never stalling on a full
ring — so you just call it in a loop:

	for {
		xsk.SendBatch(packets) // copies and transmits; returns the count queued
	}

SendFunc avoids the copy and fills each frame in place (for a generator that
varies a field per packet). The primitives underneath — Alloc, Transmit,
Complete, Kick, NumFreeTxSlots — are exported too if you want to hand-roll the
loop; if you do, remember to Kick when the ring is full or copy-mode TX
deadlocks.

# The easy path: Open

For most programs you do not need to wire up sockets and queues by hand. Open
attaches the XDP program, binds one socket per rx queue, and registers them,
all configured with functional options:

	fleet, err := afxdp.Open("eth0",
		afxdp.WithQueues(4),      // bind 4 rx queues (default: all)
		afxdp.WithUDPPorts(4789), // only UDP/4789 to us; the rest to the kernel
	)
	if err != nil {
		log.Fatal(err)
	}
	defer fleet.Close()
	for q, xsk := range fleet.Sockets() {
		go serveQueue(q, xsk) // one goroutine per queue
	}

A filter is required: without one Open would redirect every packet to your
sockets and starve the kernel (an easy way to cut off your own SSH), so it
returns an error instead. WithUDPPorts (or the more general WithFilter, which
composes Match builders like MatchUDPPort, MatchTCPPort, MatchICMPEcho,
MatchIPProto, MatchSrcIP, MatchDstIP, MatchFlow, MatchEtherType) redirects only matching packets and passes
everything else to the normal kernel stack — so you can run on a live interface
safely. Use WithFilter(MatchAll()) to deliberately take everything, or
WithFilter(MatchNone()) for transmit-only.

Open auto-selects the XDP mode: it tries native zero-copy, then native copy,
then generic copy, using the first the driver accepts, so you get the fast path
on a real NIC and it still works on veth. Fleet.Info reports the choice. Override
it only if needed with WithDriverMode, WithGenericMode, or WithZeroCopy. (Native
XDP reinitializes the driver's rings, so attaching it briefly blips the link.)
The other options (WithFrameSize, WithNumFrames, WithRingSize) tune the UMEM and
rings.

# Requirements

Introspection. Fleet.Info reports how the fleet is running (interface, queues,
frame budget, XDP mode, and whether zero-copy was granted); Fleet.Stats sums the
per-queue packet counts and the kernel's drop/error counters so you don't have
to track them yourself. Both have String methods for easy logging.

Cleanup. Call Fleet.Close (or Program.Detach) to remove the XDP program and
free the maps. Open and Program.Attach attach through a BPF link, so the kernel
auto-detaches the program when the process exits, even on a crash or kill -9
(Linux >= 5.9); on older kernels they fall back to the legacy netlink attach,
which survives a crash and must then be removed (Detach, or "ip link set dev
<iface> xdp off"). Either way Attach first clears any program left attached, so
restarting after an unclean exit just works.

AF_XDP needs CAP_NET_RAW (or root) and enough locked memory for the BPF maps
and UMEM (raise RLIMIT_MEMLOCK, e.g. ulimit -l). Native-driver (XDP_FLAGS_DRV_MODE)
zero-copy requires driver support; otherwise the kernel falls back to generic
(SKB) mode, which still works but is slower. Confirm zero-copy with
Socket.ZeroCopy after binding — some drivers need page-sized FrameSize (4096)
and a reduced MTU before they will grant it. Open sets FrameSize to 4096
automatically on AWS ENA.
*/
package afxdp
