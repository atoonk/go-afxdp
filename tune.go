//go:build linux

// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Auto-tuning defaults for NAPI batching, measured on a 100G mlx5 sink taking
// 118.8 Mpps across 48 queues:
//
//	kernel default (0/0)          18 packets per wakeup, 5.7M wakeups/s, 36.5 of 48 cores
//	defer 2, flush 200us          74 packets per wakeup, 1.6M wakeups/s, 14.0 of 48 cores
//
// Same throughput for well under half the machine. The reason is that the
// kernel wakes an AF_XDP receiver once per NAPI poll, and left to itself it
// polls far too eagerly: with a fast XDP program almost nothing has accumulated
// by the time it runs, so the fixed cost of a wakeup — interrupt dispatch,
// syscall entry, poll bookkeeping — is paid for a handful of packets instead of
// dozens. Deferring lets packets accumulate so each wakeup is worth making.
//
// Do not raise these much further. At defer 10 / flush 500us the same sink fell
// to 77 Mpps with 29M discards a second, because NAPI no longer ran often
// enough to keep the rings drained.
const (
	defaultNAPIDeferHardIRQs = 2
	defaultGROFlushTimeout   = 200 * time.Microsecond
)

// napiTuning remembers an interface's original NAPI settings so Close can put
// them back. These are properties of the netdev, not of our process: they
// outlive us, they affect the kernel's own traffic on that interface, and
// nothing restores them if we are killed. That is why they are saved verbatim,
// restored on Close, refcounted per interface, and reported by Fleet.Info
// rather than applied silently.
type napiTuning struct {
	iface      string
	savedDefer string
	savedGRO   string
	desc       string // e.g. "defer=2 flush=200µs"
}

// Interfaces can carry more than one Fleet, so the first fleet to open one
// saves and applies, and the last to close restores. Without the refcount a
// second fleet would save the already-tuned values as if they were the
// originals, and closing out of order would leave the box tuned forever.
var (
	tuningMu   sync.Mutex
	tuningRefs = make(map[string]*tuningRef)
)

type tuningRef struct {
	tuning *napiTuning
	n      int
}

func napiSysfsPath(iface, attr string) string {
	return filepath.Join("/sys/class/net", iface, attr)
}

// applyNAPITuning defers NAPI on iface so packets batch, returning a handle
// that restores the previous settings.
//
// It is entirely best-effort: on a kernel without these attributes, a read-only
// /sys (containers), or without the privileges to write them, it returns nil and
// the caller carries on untuned. Tuning is an optimisation, never a reason for
// Open to fail.
func applyNAPITuning(iface string, deferIRQs int, flush time.Duration) *napiTuning {
	tuningMu.Lock()
	defer tuningMu.Unlock()

	if ref, ok := tuningRefs[iface]; ok {
		ref.n++ // already tuned by another fleet
		return ref.tuning
	}

	savedDefer, err := readSysfs(iface, "napi_defer_hard_irqs")
	if err != nil {
		return nil
	}
	savedGRO, err := readSysfs(iface, "gro_flush_timeout")
	if err != nil {
		return nil
	}
	// gro_flush_timeout is in nanoseconds.
	if err := writeSysfs(iface, "napi_defer_hard_irqs", strconv.Itoa(deferIRQs)); err != nil {
		return nil
	}
	if err := writeSysfs(iface, "gro_flush_timeout", strconv.FormatInt(flush.Nanoseconds(), 10)); err != nil {
		// Put the first one back rather than leaving the pair half-applied.
		_ = writeSysfs(iface, "napi_defer_hard_irqs", savedDefer)
		return nil
	}

	t := &napiTuning{
		iface:      iface,
		savedDefer: savedDefer,
		savedGRO:   savedGRO,
		desc:       fmt.Sprintf("defer=%d flush=%v", deferIRQs, flush),
	}
	tuningRefs[iface] = &tuningRef{tuning: t, n: 1}
	return t
}

// restore puts the interface's original NAPI settings back once the last fleet
// using them has closed. Safe on a nil receiver so callers need no check.
func (t *napiTuning) restore() {
	if t == nil {
		return
	}
	tuningMu.Lock()
	defer tuningMu.Unlock()

	ref, ok := tuningRefs[t.iface]
	if !ok {
		return
	}
	if ref.n--; ref.n > 0 {
		return // another fleet is still using this interface
	}
	delete(tuningRefs, t.iface)
	_ = writeSysfs(t.iface, "napi_defer_hard_irqs", t.savedDefer)
	_ = writeSysfs(t.iface, "gro_flush_timeout", t.savedGRO)
}

// String renders the tuning for Fleet.Info, so what we changed on the host is
// visible in the line applications already log at startup.
func (t *napiTuning) String() string {
	if t == nil {
		return "untuned"
	}
	return t.desc
}

func readSysfs(iface, attr string) (string, error) {
	b, err := os.ReadFile(napiSysfsPath(iface, attr))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeSysfs(iface, attr, value string) error {
	return os.WriteFile(napiSysfsPath(iface, attr), []byte(value), 0o644)
}
