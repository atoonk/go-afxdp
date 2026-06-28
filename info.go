// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
)

// Info is a snapshot of how a Fleet is running: which interface, how many
// queues, the frame budget, the XDP attach mode, and whether the kernel granted
// zero-copy. It is meant to be logged at startup. Info has a String method, so:
//
//	info, _ := fleet.Info()
//	log.Print(info) // eth0: 4 queues, zero-copy, native XDP, 4096x2048B frames
type Info struct {
	Interface string // interface name
	Ifindex   int    // interface index
	Driver    string // NIC driver (e.g. "ena", "ixgbe", "mlx5_core"); "" if unknown
	NumQueues int    // sockets/queues bound
	FrameSize int    // bytes per UMEM frame
	NumFrames int    // UMEM frames per socket
	ZeroCopy  bool   // true only if every queue is in zero-copy mode
	XDPMode   string // "native", "generic", "hardware", "none", or "unknown"
	Filter    string // the applied XDP filter, e.g. "udp/53", "udp/4789 | icmp-echo", or "all"
}

// Info gathers a snapshot describing how the Fleet is running. The zero-copy
// flag is read from each socket's XDP_OPTIONS (the authoritative source, not
// just what was requested at bind); the XDP mode is read back from the kernel
// via netlink.
func (f *Fleet) Info() (Info, error) {
	info := Info{
		Interface: f.iface,
		Ifindex:   f.ifindex,
		Driver:    interfaceDriver(f.iface),
		NumQueues: len(f.sockets),
		FrameSize: f.opts.FrameSize,
		NumFrames: f.opts.NumFrames,
		Filter:    f.filter,
		XDPMode:   "unknown",
	}

	// Zero-copy is true only if every queue got it.
	info.ZeroCopy = len(f.sockets) > 0
	for _, xsk := range f.sockets {
		zc, err := xsk.ZeroCopy()
		if err != nil {
			return info, err
		}
		if !zc {
			info.ZeroCopy = false
		}
	}

	if link, err := netlink.LinkByIndex(f.ifindex); err == nil {
		info.XDPMode = xdpModeString(link.Attrs().Xdp)
	}
	return info, nil
}

// String renders Info as a single human-readable line.
func (i Info) String() string {
	zc := "copy"
	if i.ZeroCopy {
		zc = "zero-copy"
	}
	s := fmt.Sprintf("%s: %d queues, %s, %s XDP, %dx%dB frames",
		i.Interface, i.NumQueues, zc, i.XDPMode, i.NumFrames, i.FrameSize)
	if i.Driver != "" {
		s += ", driver " + i.Driver
	}
	if i.Filter != "" {
		s += ", filter " + i.Filter
	}
	return s
}

// interfaceDriver returns the kernel driver bound to an interface (from
// /sys/class/net/<iface>/device/driver), or "" for virtual devices (veth, etc.)
// or when it can't be determined.
func interfaceDriver(iface string) string {
	dest, err := os.Readlink(filepath.Join("/sys/class/net", iface, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(dest)
}

// IFLA_XDP_ATTACHED modes from linux/if_link.h (not exported by x/sys/unix).
const (
	xdpAttachedNone  = 0
	xdpAttachedDrv   = 1
	xdpAttachedSkb   = 2
	xdpAttachedHw    = 3
	xdpAttachedMulti = 4
)

func xdpModeString(x *netlink.LinkXdp) string {
	if x == nil || !x.Attached {
		return "none"
	}
	switch x.AttachMode {
	case xdpAttachedDrv:
		return "native"
	case xdpAttachedSkb:
		return "generic"
	case xdpAttachedHw:
		return "hardware"
	case xdpAttachedMulti:
		return "multi"
	case xdpAttachedNone:
		return "none"
	default:
		return "unknown"
	}
}

// FleetStats aggregates per-socket counters across every queue in the Fleet, so
// you don't have to sum them yourself. Packet counts come from the rings (no
// work needed in your receive loop); the drop/error counters come from the
// kernel's XDP_STATISTICS. Byte counts are not included — the kernel does not
// track them, so count bytes in your receive loop if you need them.
//
// All counters are cumulative since the sockets were opened; sample twice and
// subtract for a rate.
type FleetStats struct {
	Queues int

	RxPackets uint64 // received descriptors, summed over queues
	TxPackets uint64 // transmitted descriptors, summed over queues

	RxDropped       uint64 // kernel: packets dropped (e.g. no rx ring space)
	RxInvalidDescs  uint64 // kernel: bad descriptors on the fill ring
	TxInvalidDescs  uint64 // kernel: bad descriptors on the tx ring
	RxRingFull      uint64 // kernel: drops because the rx ring was full
	RxFillRingEmpty uint64 // kernel: rx starved because the fill ring was empty
	TxRingEmpty     uint64 // kernel: tx ring had nothing to send

	// PerQueue holds the raw per-socket Stats, indexed by queue id, for when
	// you need to see which queue is hot or dropping.
	PerQueue []Stats
}

// Stats aggregates statistics across all of the Fleet's sockets.
func (f *Fleet) Stats() (FleetStats, error) {
	fs := FleetStats{Queues: len(f.sockets), PerQueue: make([]Stats, 0, len(f.sockets))}
	for q, xsk := range f.sockets {
		s, err := xsk.Stats()
		if err != nil {
			return fs, fmt.Errorf("afxdp: stats for queue %d: %w", q, err)
		}
		fs.PerQueue = append(fs.PerQueue, s)
		fs.RxPackets += s.Received
		fs.TxPackets += s.Transmitted // kernel consumed from the tx ring (sent)
		fs.RxDropped += s.KernelStats.Rx_dropped
		fs.RxInvalidDescs += s.KernelStats.Rx_invalid_descs
		fs.TxInvalidDescs += s.KernelStats.Tx_invalid_descs
		fs.RxRingFull += s.KernelStats.Rx_ring_full
		fs.RxFillRingEmpty += s.KernelStats.Rx_fill_ring_empty_descs
		fs.TxRingEmpty += s.KernelStats.Tx_ring_empty_descs
	}
	return fs, nil
}

// String renders FleetStats as a single human-readable line.
func (s FleetStats) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "rx=%d tx=%d packets", s.RxPackets, s.TxPackets)
	if drops := s.RxDropped + s.RxRingFull; drops > 0 {
		fmt.Fprintf(&b, ", rx_drops=%d", drops)
	}
	if inval := s.RxInvalidDescs + s.TxInvalidDescs; inval > 0 {
		fmt.Fprintf(&b, ", invalid_descs=%d", inval)
	}
	if s.RxFillRingEmpty > 0 {
		fmt.Fprintf(&b, ", fill_empty=%d", s.RxFillRingEmpty)
	}
	return b.String()
}
