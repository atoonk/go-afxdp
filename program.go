// Copyright 2024 Andree Toonk. All rights reserved.
// Portions Copyright 2019 Asavie Technologies Ltd.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Program is the small XDP BPF program that redirects packets on a given rx
// queue to the AF_XDP socket registered for that queue. It is the standard
// xsk redirect program (a translation of xsk_load_xdp_prog from libbpf).
type Program struct {
	Program *ebpf.Program
	Queues  *ebpf.Map // qidconf_map: queue id -> enabled
	Sockets *ebpf.Map // xsks_map: queue id -> socket fd

	// link is non-nil when the program was attached via a BPF link (the
	// preferred path): the kernel auto-detaches it when this process exits,
	// even on a crash. When nil, the program was attached via the legacy
	// netlink path and must be detached explicitly (it survives a crash).
	link link.Link
}

// NewProgram builds the redirect program with room for maxQueues queue entries.
// Register one socket per queue with Register before traffic will be delivered.
func NewProgram(maxQueues int) (*Program, error) {
	qidconf, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "qidconf_map",
		Type:       ebpf.Array,
		KeySize:    uint32(unsafe.Sizeof(int32(0))),
		ValueSize:  uint32(unsafe.Sizeof(int32(0))),
		MaxEntries: uint32(maxQueues),
	})
	if err != nil {
		return nil, fmt.Errorf("afxdp: create qidconf_map (try raising RLIMIT_MEMLOCK): %w", err)
	}
	xsks, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "xsks_map",
		Type:       ebpf.XSKMap,
		KeySize:    uint32(unsafe.Sizeof(int32(0))),
		ValueSize:  uint32(unsafe.Sizeof(int32(0))),
		MaxEntries: uint32(maxQueues),
	})
	if err != nil {
		qidconf.Close()
		return nil, fmt.Errorf("afxdp: create xsks_map (try raising RLIMIT_MEMLOCK): %w", err)
	}

	// Translation of the default xsk redirect program; see
	// <linux>/tools/lib/bpf/xsk.c xsk_load_xdp_prog().
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "xsk_redirect",
		Type: ebpf.XDP,
		Instructions: asm.Instructions{
			{OpCode: 97, Dst: 1, Src: 1, Offset: 16},
			{OpCode: 99, Dst: 10, Src: 1, Offset: -4},
			{OpCode: 191, Dst: 2, Src: 10},
			{OpCode: 7, Dst: 2, Src: 0, Offset: 0, Constant: -4},
			{OpCode: 24, Dst: 1, Src: 1, Offset: 0, Constant: int64(qidconf.FD())},
			{OpCode: 133, Dst: 0, Src: 0, Constant: 1},
			{OpCode: 191, Dst: 1, Src: 0},
			{OpCode: 180, Dst: 0, Src: 0},
			{OpCode: 21, Dst: 1, Src: 0, Offset: 8},
			{OpCode: 180, Dst: 0, Src: 0, Constant: 2},
			{OpCode: 97, Dst: 1, Src: 1},
			{OpCode: 21, Dst: 1, Offset: 5},
			{OpCode: 24, Dst: 1, Src: 1, Constant: int64(xsks.FD())},
			{OpCode: 97, Dst: 2, Src: 10, Offset: -4},
			{OpCode: 180, Dst: 3},
			{OpCode: 133, Constant: 51},
			{OpCode: 149},
		},
		License: "LGPL-2.1 or BSD-2-Clause",
	})
	if err != nil {
		qidconf.Close()
		xsks.Close()
		return nil, fmt.Errorf("afxdp: load XDP program: %w", err)
	}
	return &Program{Program: prog, Queues: qidconf, Sockets: xsks}, nil
}

// Attach attaches the program to the interface using the given XDP flags
// (0, unix.XDP_FLAGS_DRV_MODE, unix.XDP_FLAGS_SKB_MODE, ...). Any program left
// over from a previous run is removed first.
//
// It prefers a BPF link, which the kernel auto-detaches when this process
// exits — so the redirect program is cleaned up even if the process is killed
// or crashes. On kernels too old for XDP links (< 5.9) it falls back to the
// legacy netlink attach, which survives a crash and must then be removed
// manually (Detach, or "ip link set dev <iface> xdp off").
func (p *Program) Attach(ifindex int, xdpFlags uint32) error {
	if err := removeProgram(ifindex); err != nil {
		return err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   p.Program,
		Interface: ifindex,
		Flags:     link.XDPAttachFlags(xdpFlags),
	})
	if err == nil {
		p.link = l
		return nil
	}
	// Only fall back when XDP links aren't supported by the kernel; surface
	// any other failure (e.g. the driver rejecting the requested mode).
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("afxdp: attach XDP program (link): %w", err)
	}

	nl, err2 := netlink.LinkByIndex(ifindex)
	if err2 != nil {
		return err2
	}
	if err2 := netlink.LinkSetXdpFdWithFlags(nl, p.Program.FD(), int(xdpFlags)); err2 != nil {
		return fmt.Errorf("afxdp: attach XDP program (netlink fallback): %w", err2)
	}
	return nil
}

// Detach removes the program from the interface. For a link-attached program it
// closes the link; otherwise it removes the netlink-attached program.
func (p *Program) Detach(ifindex int) error {
	if p.link != nil {
		err := p.link.Close()
		p.link = nil
		return err
	}
	return removeProgram(ifindex)
}

// Register routes packets arriving on queueID to the socket with the given fd.
// For a pass-only program (no redirect maps, e.g. from MatchNone) it is a
// no-op: there is nothing to route.
func (p *Program) Register(queueID, fd int) error {
	if p.Sockets == nil || p.Queues == nil {
		return nil
	}
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return fmt.Errorf("afxdp: register socket for queue %d: %w", queueID, err)
	}
	if err := p.Queues.Put(uint32(queueID), uint32(1)); err != nil {
		return fmt.Errorf("afxdp: enable queue %d: %w", queueID, err)
	}
	return nil
}

// Unregister stops routing packets for queueID to any socket. It is a no-op for
// a pass-only program (no redirect maps).
func (p *Program) Unregister(queueID int) error {
	if p.Sockets == nil || p.Queues == nil {
		return nil
	}
	// qidconf is a BPF array map, which does not support delete; disable the
	// queue by setting its entry to 0 instead.
	if err := p.Queues.Put(uint32(queueID), uint32(0)); err != nil {
		return err
	}
	return p.Sockets.Delete(uint32(queueID))
}

// Close releases the program and its maps. If the program is still attached via
// a BPF link, the link is closed too (detaching it); a netlink-attached program
// must be removed with Detach.
func (p *Program) Close() error {
	var firstErr error
	if p.link != nil {
		if err := p.link.Close(); err != nil {
			firstErr = err
		}
		p.link = nil
	}
	if p.Sockets != nil {
		if err := p.Sockets.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.Sockets = nil
	}
	if p.Queues != nil {
		if err := p.Queues.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.Queues = nil
	}
	if p.Program != nil {
		if err := p.Program.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		p.Program = nil
	}
	return firstErr
}

func removeProgram(ifindex int) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return err
	}
	if !xdpAttached(link) {
		return nil
	}
	if err := netlink.LinkSetXdpFd(link, -1); err != nil {
		// The usual cause: the attached program belongs to a live process that
		// holds it via a BPF link, which netlink cannot remove — another
		// XDP/AF_XDP app owns this interface right now. Name the program so
		// the owner can be tracked down (bpftool prog show id N, or scan
		// /proc/*/fd for bpf holders) instead of surfacing a bare EBUSY.
		id := uint32(0)
		if a := link.Attrs(); a != nil && a.Xdp != nil {
			id = a.Xdp.ProgId
		}
		return fmt.Errorf("afxdp: XDP program id %d is already attached to %s and cannot be removed — likely owned by another running process; stop that process first: %w",
			id, link.Attrs().Name, err)
	}
	for {
		link, err = netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		if !xdpAttached(link) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func xdpAttached(link netlink.Link) bool {
	a := link.Attrs()
	return a != nil && a.Xdp != nil && a.Xdp.Attached
}

// re-export of unix XDP attach-mode flags so callers need not import unix.
const (
	XDPFlagsDrvMode = unix.XDP_FLAGS_DRV_MODE
	XDPFlagsSkbMode = unix.XDP_FLAGS_SKB_MODE
	XDPFlagsHwMode  = unix.XDP_FLAGS_HW_MODE
)
