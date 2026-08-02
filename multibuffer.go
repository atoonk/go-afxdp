//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Packet is one received packet: a single Desc when it fits one UMEM frame, or
// several chained descriptors when the packet is larger than the frame size and
// the socket was bound with multi-buffer enabled (see WithMultiBuffer).
//
// The fragments are in wire order, so concatenating their frames reconstructs
// the packet. Only the first fragment holds the headers.
type Packet []Desc

// Len returns the packet's total length in bytes, summed over its fragments.
func (p Packet) Len() int {
	n := 0
	for _, d := range p {
		n += int(d.Len)
	}
	return n
}

// maxTxSegs bounds how many frames one transmitted packet may span.
//
// In copy mode the kernel builds an skb from the chain, so the ceiling is
// CONFIG_MAX_SKB_FRAGS + 1 (one head plus the frags), which is 18 on a stock
// kernel. Chains longer than that are rejected by the kernel rather than sent,
// so catching it here turns a confusing failure into a clear error. A device
// may allow fewer in zero-copy mode, where it reports its own limit as
// xdp-zc-max-segs, but a socket bound with XDP_USE_SG only gets zero-copy on
// devices whose limit is at least 2, and no MTU in practice needs more than a
// handful of frames.
const maxTxSegs = 18

// multiBuffer reports whether this socket was bound with XDP_USE_SG. Without
// it the kernel drops every multi-buffer packet before it reaches the rx ring,
// so chains can only ever appear when this is true.
func (xsk *Socket) multiBuffer() bool {
	return xsk.options.BindFlags&unix.XDP_USE_SG != 0
}

// ReceivePackets consumes up to maxFrames descriptors from the rx ring and
// groups them into whole packets. It is the multi-buffer-aware counterpart of
// Receive: use it whenever WithMultiBuffer is in play, because Receive returns
// one Desc per *frame* and a jumbo packet would look like several unrelated
// descriptors.
//
// The budget is in frames, not packets, so with chained packets the returned
// slice is shorter than maxFrames. When multi-buffer is off every packet has
// exactly one fragment and this is equivalent to Receive.
//
// A chain can straddle two calls when the batch boundary falls mid-packet. Such
// a partial chain is held inside the Socket and completed on a later call — a
// packet is never returned before its last fragment has arrived, so the caller
// never sees a truncated packet.
//
// The returned slice and the Descs it points at are owned by the Socket and
// reused on the next call; copy out anything you need to keep. Return the
// frames with RecyclePackets when done.
func (xsk *Socket) ReceivePackets(maxFrames int) []Packet {
	if !xsk.incref() {
		return nil
	}
	defer xsk.decref()

	descs := xsk.Receive(maxFrames)
	if len(descs) == 0 && len(xsk.pktPartial) == 0 {
		return nil
	}

	// Build one stable backing array of carried-over fragments plus the new
	// ones, then slice packets out of it. Assembling it fully before slicing
	// means no append can reallocate under a Packet we already handed out.
	need := len(xsk.pktPartial) + len(descs)
	if cap(xsk.pktDescs) < need {
		xsk.pktDescs = make([]Desc, 0, need)
	}
	buf := append(xsk.pktDescs[:0], xsk.pktPartial...)
	buf = append(buf, descs...)
	xsk.pktDescs = buf
	xsk.pktPartial = xsk.pktPartial[:0]

	pkts := xsk.pktScratch[:0]
	start := 0
	for i := range buf {
		// XDP_PKT_CONTD means "continues in the next descriptor", so the
		// fragment that ends a packet is the one with the bit clear.
		if buf[i].Options&unix.XDP_PKT_CONTD == 0 {
			pkts = append(pkts, Packet(buf[start:i+1]))
			start = i + 1
		}
	}
	if start < len(buf) { // incomplete tail: hold it for the next call
		xsk.pktPartial = append(xsk.pktPartial[:0], buf[start:]...)
	}
	xsk.pktScratch = pkts
	return pkts
}

// RecyclePackets returns every fragment of every packet to the receive pool so
// a later Fill can hand them back to the kernel. It is Recycle for the packets
// ReceivePackets produced.
func (xsk *Socket) RecyclePackets(pkts []Packet) {
	for _, p := range pkts {
		for _, d := range p {
			xsk.rxPool.push(xsk.frameBase(d.Addr))
		}
	}
}

// CopyOut flattens a packet's fragments into dst and returns the number of
// bytes written, which is min(p.Len(), len(dst)). Use it when downstream code
// needs one contiguous buffer; walk the fragments yourself to avoid the copy.
func (xsk *Socket) CopyOut(p Packet, dst []byte) int {
	n := 0
	for _, d := range p {
		if n >= len(dst) {
			break
		}
		n += copy(dst[n:], xsk.GetFrame(d))
	}
	return n
}

// sendBatchSG is SendBatch for a multi-buffer socket: payloads longer than one
// frame are split across several, with XDP_PKT_CONTD set on every fragment but
// the last. It returns the number of whole payloads queued.
func (xsk *Socket) sendBatchSG(payloads [][]byte) (int, error) {
	if !xsk.incref() {
		return 0, net.ErrClosed
	}
	defer xsk.decref()

	xsk.Complete(xsk.NumCompleted()) // reclaim already-sent frames
	free := xsk.NumFreeTxSlots()
	if free == 0 {
		// Ring full: kick so the kernel drains it and produces completions.
		if xsk.kickNeeded() {
			_ = xsk.Kick()
		} else {
			xsk.statKicksSuppressed.Add(1)
		}
		return 0, nil
	}

	fs := xsk.options.FrameSize
	frames := func(p []byte) int {
		if n := (len(p) + fs - 1) / fs; n > 0 {
			return n
		}
		return 1 // a zero-length payload still occupies one descriptor
	}

	// Reject an over-long chain up front and queue nothing, the same contract
	// SendBatch uses for an oversized payload on a non-multi-buffer socket.
	// The kernel would refuse the chain anyway; failing here says why.
	for i, p := range payloads {
		if n := frames(p); n > maxTxSegs {
			return 0, fmt.Errorf("afxdp: SendBatch payload %d is %d bytes, needing %d frames of %d "+
				"bytes, more than the %d a single packet may span", i, len(p), n, fs, maxTxSegs)
		}
	}

	// Take whole packets only. A chain cut short by ring space would put a
	// bare fragment on the wire as though it were a complete packet.
	fit := func(budget int) (nFrames, nPkts int) {
		for _, p := range payloads {
			f := frames(p)
			if nFrames+f > budget {
				break
			}
			nFrames += f
			nPkts++
		}
		return
	}

	nFrames, nPkts := fit(free)
	if nPkts == 0 {
		return 0, nil
	}
	descs := xsk.Alloc(nFrames)
	if len(descs) < nFrames {
		// The transmit pool came up short. Re-fit to what we actually got and
		// hand the leftover frames back rather than leaking them.
		nFrames, nPkts = fit(len(descs))
		for _, d := range descs[nFrames:] {
			xsk.txPool.push(xsk.frameBase(d.Addr))
		}
		descs = descs[:nFrames]
		if nPkts == 0 {
			return 0, nil
		}
	}

	k := 0
	for i := 0; i < nPkts; i++ {
		p := payloads[i]
		f := frames(p)
		off := 0
		for j := 0; j < f; j++ {
			n := copy(xsk.GetFrame(descs[k]), p[off:])
			off += n
			descs[k].Len = uint32(n)
			if j < f-1 {
				descs[k].Options = unix.XDP_PKT_CONTD
			} else {
				descs[k].Options = 0
			}
			k++
		}
	}

	sent := xsk.Transmit(descs)
	// Transmit caps at the free ring space we already fit inside, so this is
	// normally all of them. Count packets, not frames, and only those whose
	// final fragment made it onto the ring.
	queued := 0
	for _, d := range descs[:sent] {
		if d.Options&unix.XDP_PKT_CONTD == 0 {
			queued++
		}
	}
	return queued, nil
}
