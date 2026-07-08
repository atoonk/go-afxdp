//go:build linux

package afxdp

import "testing"

func TestFramePoolPopPush(t *testing.T) {
	p := newFramePool(0, 4, 2048)
	if got := p.len(); got != 4 {
		t.Fatalf("len = %d, want 4", got)
	}

	var dst []uint64
	dst = p.pop(3, dst)
	if len(dst) != 3 {
		t.Fatalf("popped %d, want 3", len(dst))
	}
	if p.len() != 1 {
		t.Fatalf("len after pop = %d, want 1", p.len())
	}

	// Asking for more than available returns only what's free.
	dst = p.pop(10, dst[:0])
	if len(dst) != 1 {
		t.Fatalf("popped %d, want 1 (pool nearly empty)", len(dst))
	}
	if p.len() != 0 {
		t.Fatalf("len = %d, want 0", p.len())
	}

	// Empty pool yields nothing, no panic.
	if got := p.pop(5, nil); len(got) != 0 {
		t.Fatalf("pop on empty returned %d", len(got))
	}

	p.push(4096)
	if p.len() != 1 {
		t.Fatalf("len after push = %d, want 1", p.len())
	}
}

// TestSplitPoolsDisjoint is the property that makes a Socket safe to drive from
// a receive goroutine and a transmit goroutine at once: the two pools never
// share a frame address. This mirrors how NewSocket partitions the UMEM.
func TestSplitPoolsDisjoint(t *testing.T) {
	const numFrames, txFrames, frameSize = 8, 3, 2048
	rxFrames := numFrames - txFrames
	rx := newFramePool(0, rxFrames, frameSize)
	tx := newFramePool(rxFrames, txFrames, frameSize)

	seen := map[uint64]string{}
	var buf []uint64
	for _, a := range rx.pop(rxFrames, buf[:0]) {
		seen[a] = "rx"
	}
	for _, a := range tx.pop(txFrames, buf[:0]) {
		if who, ok := seen[a]; ok {
			t.Fatalf("frame addr %d in both %s and tx pools", a, who)
		}
		seen[a] = "tx"
	}
	if len(seen) != numFrames {
		t.Fatalf("covered %d distinct frames, want %d", len(seen), numFrames)
	}

	// Transmit frames must start past the receive region.
	for a := range seen {
		if seen[a] == "tx" && a < uint64(rxFrames*frameSize) {
			t.Fatalf("tx frame %d overlaps rx region [0,%d)", a, rxFrames*frameSize)
		}
	}
}
