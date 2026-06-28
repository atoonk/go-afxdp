// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

// framePool is a LIFO free-list of UMEM frame addresses for one direction
// (receive or transmit).
//
// CONCURRENCY: a framePool is NOT internally synchronized. Each pool is owned
// by exactly one goroutine — the receive pool by the receive goroutine, the
// transmit pool by the transmit goroutine. Because the receive and transmit
// pools hold disjoint frame addresses and are touched by different goroutines,
// no locking is required on the data path. This is the core of the fork: the
// upstream asavie/xdp shared a single freeDescs slice across both directions,
// so a concurrent fill and transmit handed out the same frame and corrupted
// packets on the wire. Splitting the pool removes the shared state entirely.
//
// If you drive transmit from multiple producer goroutines, serialize the
// transmit-side calls yourself (the receive side still needs no lock).
type framePool struct {
	free []uint64 // stack of free frame addresses
}

// newFramePool builds a pool of count frames starting at frame index base,
// each frameSize bytes apart. The frames occupy
// [base, base+count) * frameSize within the UMEM.
func newFramePool(base, count, frameSize int) *framePool {
	p := &framePool{free: make([]uint64, count)}
	for i := 0; i < count; i++ {
		p.free[i] = uint64((base + i) * frameSize)
	}
	return p
}

// len returns how many frames are currently free.
func (p *framePool) len() int { return len(p.free) }

// pop removes and returns up to n free frame addresses, appending them to dst.
// It returns the (possibly grown) dst slice. If fewer than n frames are free,
// it returns as many as are available.
func (p *framePool) pop(n int, dst []uint64) []uint64 {
	if n > len(p.free) {
		n = len(p.free)
	}
	if n == 0 {
		return dst
	}
	start := len(p.free) - n
	dst = append(dst, p.free[start:]...)
	p.free = p.free[:start]
	return dst
}

// push returns a single frame address to the pool.
func (p *framePool) push(addr uint64) {
	p.free = append(p.free, addr)
}
