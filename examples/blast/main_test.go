//go:build linux

package main

import (
	"testing"

	"golang.org/x/time/rate"
)

func TestNewLimiter(t *testing.T) {
	tests := []struct {
		pps       int
		wantBurst int
	}{
		{100_000_000, 1_000_000}, // 10ms of credit at 100M pps
		{5_000_000, 50_000},      // 10ms at 5M pps (a per-queue 100G rate)
		{1000, 4 * batch},        // tiny rate: floored so a whole batch still fits
		{100, 4 * batch},         // floor again
	}
	for _, tc := range tests {
		lim := newLimiter(tc.pps)
		if got := lim.Burst(); got != tc.wantBurst {
			t.Errorf("newLimiter(%d).Burst() = %d, want %d", tc.pps, got, tc.wantBurst)
		}
		if got := lim.Limit(); got != rate.Limit(tc.pps) {
			t.Errorf("newLimiter(%d).Limit() = %v, want %d", tc.pps, got, tc.pps)
		}
		// The bucket must always hold at least one batch, or WaitN(batch) can
		// never succeed and a paced blast would hang.
		if lim.Burst() < batch {
			t.Errorf("newLimiter(%d) burst %d < batch %d: WaitN(batch) would hang", tc.pps, lim.Burst(), batch)
		}
	}
}

func TestPacingChunk(t *testing.T) {
	// burst here stands in for lim.Burst(); use a large value so the cap is not
	// the binding constraint except in the explicit cap case.
	tests := []struct {
		pps, override, burst, want int
	}{
		{5_000_000, 0, 50_000, 2304},    // ~500µs at 5M/queue, rounded to 9 batches
		{2_000_000, 0, 40_000, 768},     // ~500µs at 2M/queue, 3 batches
		{1000, 0, 1024, batch},          // tiny rate floors at one batch
		{5_000_000, 1024, 50_000, 1024}, // override wins
		{5_000_000, 0, 1024, 1024},      // capped to the bucket, whole batches
		{5_000_000, 300, 50_000, 256},   // override below a batch floors up
	}
	for _, tc := range tests {
		got := pacingChunk(tc.pps, tc.override, tc.burst)
		if got != tc.want {
			t.Errorf("pacingChunk(pps=%d, override=%d, burst=%d) = %d, want %d", tc.pps, tc.override, tc.burst, got, tc.want)
		}
		if got%batch != 0 {
			t.Errorf("pacingChunk(...) = %d is not a whole number of batches (%d)", got, batch)
		}
		if got > tc.burst {
			t.Errorf("pacingChunk(...) = %d exceeds burst %d; WaitN would hang", got, tc.burst)
		}
	}
}

func TestSplitRate(t *testing.T) {
	tests := []struct {
		total, n int
		wantNil  bool
	}{
		{0, 8, true},
		{-5, 8, true},
		{100_000_000, 20, false},
		{20, 20, false}, // exactly one per queue
		{25, 20, false}, // remainder to queue 0
		{1, 1, false},
	}
	for _, tc := range tests {
		shares := splitRate(tc.total, tc.n)
		if tc.wantNil {
			if shares != nil {
				t.Errorf("splitRate(%d,%d) = %v, want nil", tc.total, tc.n, shares)
			}
			continue
		}
		sum := 0
		for i, s := range shares {
			if s < 1 {
				t.Errorf("splitRate(%d,%d) share %d = %d, want >= 1 (a zero share reads as unpaced)", tc.total, tc.n, i, s)
			}
			sum += s
		}
		if sum != tc.total {
			t.Errorf("splitRate(%d,%d) sums to %d, want %d", tc.total, tc.n, sum, tc.total)
		}
	}
}
