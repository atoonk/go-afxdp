// Copyright 2024 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// A Match is one packet-classification rule for WithFilter. A packet is
// redirected to the AF_XDP sockets if it satisfies ANY of the matches (logical
// OR); everything else is passed to the kernel network stack. Build matches
// with MatchUDPPort, MatchTCPPort, MatchICMPEcho, MatchIPProto, MatchEtherType,
// or MatchAll, and combine freely:
//
//	afxdp.Open("eth0", afxdp.WithFilter(
//		afxdp.MatchUDPPort(4789, 51820), // two UDP ports
//		afxdp.MatchICMPEcho(),           // ...and ICMP echo requests
//	))
//
// Matches operate on plain Ethernet + IPv4 (no VLAN tag, no IP options), which
// covers the common case. For arbitrary classification beyond these builders,
// redirect everything (no filter) and classify in your receive loop.
type Match struct {
	// build emits the eBPF for this rule. On a match it jumps to redirectSym;
	// otherwise it falls through to the physically next block (nextSym, used
	// for its early-exit jumps). entrySym labels its first instruction.
	build func(entrySym, nextSym, redirectSym string) asm.Instructions
	// desc is a short human-readable summary (e.g. "udp/53") reported by
	// Fleet.Info.
	desc string
	// err, if non-nil, is a construction error (e.g. a bad CIDR passed to
	// MatchSrcIP). Open surfaces it instead of attaching a broken program.
	err error
	// passOnly is true for a match that never redirects (MatchNone). If every
	// match is passOnly the program has no reachable redirect path, so we emit
	// a minimal pass-everything program instead (the verifier rejects the
	// unreachable redirect block otherwise).
	passOnly bool
}

// portsDesc renders a protocol + optional port list, e.g. "udp/53",
// "tcp/80,443", or just "udp" when no ports are given.
func portsDesc(proto string, ports []uint16) string {
	if len(ports) == 0 {
		return proto
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return proto + "/" + strings.Join(parts, ",")
}

// Packet field offsets for Ethernet + IPv4(no options) + L4.
const (
	offEtherType = 12 // u16
	offIPProto   = 23 // u8  (14 + 9)
	offL4Dport   = 36 // u16 (14 + 20 + 2): same for UDP and TCP
	offICMPType  = 34 // u8  (14 + 20 + 0)

	// IP address offsets. These are fixed regardless of IPv4 options or IPv6
	// extension headers, so address matching needs no header walking.
	offIPv4Src = 26 // 14 + 12, 4 bytes
	offIPv4Dst = 30 // 14 + 16, 4 bytes
	offIPv6Src = 22 // 14 + 8, 16 bytes
	offIPv6Dst = 38 // 14 + 24, 16 bytes

	etherTypeIPv4LE = 0x0008 // htons(0x0800) as seen by a little-endian load
	etherTypeIPv6LE = 0xdd86 // htons(0x86dd)
	ipProtoICMP     = 1
	ipProtoTCP      = 6
	ipProtoUDP      = 17
	icmpEchoRequest = 8
	xdpPass         = 2
)

// netshort returns the network-byte-order (big-endian) value of a port as a
// little-endian load sees it, so it can be compared against a loaded u16.
func netshort(v uint16) int32 { return int32(v<<8 | v>>8) }

func withEntry(entry string, ins asm.Instructions) asm.Instructions {
	if len(ins) > 0 {
		ins[0] = ins[0].WithSymbol(entry)
	}
	return ins
}

// boundsCheck emits "if data + n > data_end goto next".
func boundsCheck(n int32, next string) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.R7),
		asm.Add.Imm(asm.R2, n),
		asm.JGT.Reg(asm.R2, asm.R6, next),
	}
}

// MatchUDPPort matches IPv4/UDP packets whose destination port is one of ports.
// With no ports it matches all IPv4/UDP traffic.
func MatchUDPPort(ports ...uint16) Match {
	return Match{desc: portsDesc("udp", ports), build: func(entry, next, redirect string) asm.Instructions {
		ins := boundsCheck(offL4Dport+2, next)
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, etherTypeIPv4LE, next),
			asm.LoadMem(asm.R3, asm.R7, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, ipProtoUDP, next),
		)
		if len(ports) == 0 {
			ins = append(ins, asm.Ja.Label(redirect))
			return withEntry(entry, ins)
		}
		ins = append(ins, asm.LoadMem(asm.R3, asm.R7, offL4Dport, asm.Half))
		for _, p := range ports {
			ins = append(ins, asm.JEq.Imm(asm.R3, netshort(p), redirect))
		}
		// No port matched: fall through to the next block (== next).
		return withEntry(entry, ins)
	}}
}

// MatchTCPPort matches IPv4/TCP packets whose destination port is one of ports.
// With no ports it matches all IPv4/TCP traffic.
func MatchTCPPort(ports ...uint16) Match {
	return Match{desc: portsDesc("tcp", ports), build: func(entry, next, redirect string) asm.Instructions {
		ins := boundsCheck(offL4Dport+2, next)
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, etherTypeIPv4LE, next),
			asm.LoadMem(asm.R3, asm.R7, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, ipProtoTCP, next),
		)
		if len(ports) == 0 {
			ins = append(ins, asm.Ja.Label(redirect))
			return withEntry(entry, ins)
		}
		ins = append(ins, asm.LoadMem(asm.R3, asm.R7, offL4Dport, asm.Half))
		for _, p := range ports {
			ins = append(ins, asm.JEq.Imm(asm.R3, netshort(p), redirect))
		}
		return withEntry(entry, ins)
	}}
}

// MatchICMPEcho matches IPv4 ICMP echo-request (ping) packets.
func MatchICMPEcho() Match {
	return Match{desc: "icmp-echo", build: func(entry, next, redirect string) asm.Instructions {
		ins := boundsCheck(offICMPType+1, next)
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, etherTypeIPv4LE, next),
			asm.LoadMem(asm.R3, asm.R7, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, ipProtoICMP, next),
			asm.LoadMem(asm.R3, asm.R7, offICMPType, asm.Byte),
			asm.JNE.Imm(asm.R3, icmpEchoRequest, next),
			asm.Ja.Label(redirect),
		)
		return withEntry(entry, ins)
	}}
}

// MatchIPProto matches any IPv4 packet carrying the given IP protocol number
// (e.g. 47 for GRE, 50 for ESP). See MatchUDPPort/MatchTCPPort for the common
// protocols with port filtering.
func MatchIPProto(proto uint8) Match {
	return Match{desc: fmt.Sprintf("ip-proto/%d", proto), build: func(entry, next, redirect string) asm.Instructions {
		ins := boundsCheck(offIPProto+1, next)
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, etherTypeIPv4LE, next),
			asm.LoadMem(asm.R3, asm.R7, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, int32(proto), next),
			asm.Ja.Label(redirect),
		)
		return withEntry(entry, ins)
	}}
}

// MatchEtherType matches packets with the given EtherType (e.g. 0x0806 for ARP,
// 0x86DD for IPv6). Pass the value in host order; MatchEtherType handles the
// byte order.
func MatchEtherType(etherType uint16) Match {
	return Match{desc: fmt.Sprintf("ethertype/0x%04x", etherType), build: func(entry, next, redirect string) asm.Instructions {
		ins := boundsCheck(offEtherType+2, next)
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, netshort(etherType), next),
			asm.Ja.Label(redirect),
		)
		return withEntry(entry, ins)
	}}
}

// MatchSrcIP matches packets whose source IP is inside the given CIDR. The CIDR
// chooses the address family: "10.0.0.0/8" matches IPv4, "2001:db8::/32" matches
// IPv6, a single host is "/32" (v4) or "/128" (v6).
func MatchSrcIP(cidr string) Match { return matchIP(cidr, true) }

// MatchDstIP matches packets whose destination IP is inside the given CIDR. See
// MatchSrcIP for the CIDR format.
func MatchDstIP(cidr string) Match { return matchIP(cidr, false) }

// MatchFlow matches packets whose source IP is in srcCIDR AND whose destination
// IP is in dstCIDR, i.e. one direction of a flow. Both CIDRs must be the same
// address family (IPv4 with IPv4, or IPv6 with IPv6); a single host on a side is
// "/32" or "/128". To match a flow in either direction, OR two of them:
//
//	afxdp.WithFilter(
//		afxdp.MatchFlow("10.0.0.1/32", "10.0.0.2/32"),
//		afxdp.MatchFlow("10.0.0.2/32", "10.0.0.1/32"),
//	)
func MatchFlow(srcCIDR, dstCIDR string) Match {
	src, err := netip.ParsePrefix(srcCIDR)
	if err != nil {
		return Match{desc: "flow(invalid)", err: fmt.Errorf("bad src CIDR %q: %w", srcCIDR, err)}
	}
	dst, err := netip.ParsePrefix(dstCIDR)
	if err != nil {
		return Match{desc: "flow(invalid)", err: fmt.Errorf("bad dst CIDR %q: %w", dstCIDR, err)}
	}
	src, dst = src.Masked(), dst.Masked()
	if src.Addr().Is4() != dst.Addr().Is4() {
		return Match{desc: "flow(invalid)", err: fmt.Errorf("flow src %s and dst %s must be the same address family", src, dst)}
	}
	return Match{
		desc: "src " + src.String() + " & dst " + dst.String(),
		build: func(entry, next, redirect string) asm.Instructions {
			srcOff, dstOff, et, end := ipOffsets(src.Addr().Is4())
			ins := boundsCheck(int32(end), next)
			ins = append(ins,
				asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
				asm.JNE.Imm(asm.R3, int32(et), next),
			)
			ins = append(ins, cidrTest(srcOff, src, next)...) // src not in CIDR -> next
			ins = append(ins, cidrTest(dstOff, dst, next)...) // dst not in CIDR -> next
			ins = append(ins, asm.Ja.Label(redirect))         // both matched
			return withEntry(entry, ins)
		},
	}
}

func matchIP(cidr string, isSrc bool) Match {
	dir := "dst"
	if isSrc {
		dir = "src"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return Match{desc: dir + " ip(invalid)", err: fmt.Errorf("bad CIDR %q: %w", cidr, err)}
	}
	prefix = prefix.Masked()
	return Match{
		desc: dir + " " + prefix.String(),
		build: func(entry, next, redirect string) asm.Instructions {
			srcOff, dstOff, et, end := ipOffsets(prefix.Addr().Is4())
			off := dstOff
			if isSrc {
				off = srcOff
			}
			ins := boundsCheck(int32(end), next)
			ins = append(ins,
				asm.LoadMem(asm.R3, asm.R7, offEtherType, asm.Half),
				asm.JNE.Imm(asm.R3, int32(et), next),
			)
			ins = append(ins, cidrTest(off, prefix, next)...) // not in CIDR -> next
			ins = append(ins, asm.Ja.Label(redirect))         // matched
			return withEntry(entry, ins)
		},
	}
}

// ipOffsets returns the source and destination address offsets, the EtherType to
// require, and the offset just past the destination address (for the bounds
// check that covers both addresses).
func ipOffsets(isV4 bool) (srcOff, dstOff, et, end int) {
	if isV4 {
		return offIPv4Src, offIPv4Dst, etherTypeIPv4LE, offIPv4Dst + 4
	}
	return offIPv6Src, offIPv6Dst, etherTypeIPv6LE, offIPv6Dst + 16
}

// cidrTest emits "if the address at off is NOT inside prefix, jump to fail". On a
// match it falls through. The caller has already bounds-checked and confirmed the
// EtherType. The 32-bit packet loads are little-endian, so the mask and network
// words are computed the same way. IPv6 is checked word by word; words the prefix
// does not cover (zero mask) are skipped.
func cidrTest(off int, prefix netip.Prefix, fail string) asm.Instructions {
	var addr, mask []byte
	if prefix.Addr().Is4() {
		a := prefix.Addr().As4()
		addr, mask = a[:], net.CIDRMask(prefix.Bits(), 32)
	} else {
		a := prefix.Addr().As16()
		addr, mask = a[:], net.CIDRMask(prefix.Bits(), 128)
	}
	var ins asm.Instructions
	for w := 0; w*4 < len(mask); w++ {
		mw := binary.LittleEndian.Uint32(mask[w*4:])
		if mw == 0 {
			continue
		}
		nw := binary.LittleEndian.Uint32(addr[w*4:]) & mw
		ins = append(ins,
			asm.LoadMem(asm.R3, asm.R7, int16(off+w*4), asm.Word),
			asm.And.Imm(asm.R3, int32(mw)),
			asm.JNE.Imm32(asm.R3, int32(nw), fail),
		)
	}
	return ins
}

// MatchAll matches every packet. Use it as a catch-all, or on its own it is
// equivalent to running with no filter at all.
func MatchAll() Match {
	return Match{desc: "all", build: func(entry, _, redirect string) asm.Instructions {
		return withEntry(entry, asm.Instructions{asm.Ja.Label(redirect)})
	}}
}

// MatchNone matches nothing: every packet is passed to the kernel, none is
// redirected. On its own (afxdp.WithFilter(afxdp.MatchNone())) it attaches the
// XDP program — which is what enables a driver's zero-copy datapath — without
// stealing any receive traffic. That's exactly what a transmit-only program
// (a packet generator) wants: zero-copy TX without disturbing the host's RX.
func MatchNone() Match {
	return Match{
		desc:     "none",
		passOnly: true,
		build: func(entry, next, _ string) asm.Instructions {
			return withEntry(entry, asm.Instructions{asm.Ja.Label(next)})
		},
	}
}

// filterDesc renders a set of matches as a short human-readable summary, e.g.
// "udp/53" or "udp/4789 | icmp-echo". No matches means the program redirects
// everything, reported as "all".
func filterDesc(matches []Match) string {
	if len(matches) == 0 {
		return "all"
	}
	descs := make([]string, len(matches))
	for i, m := range matches {
		descs[i] = m.desc
	}
	return strings.Join(descs, " | ")
}

// newFilterProgram assembles an XDP program from the given matches. A packet is
// redirected if any match matches; otherwise it is passed to the kernel. The
// redirect path reuses the same qidconf gate + redirect_map tail as NewProgram,
// so binding a subset of queues stays safe (unbound queues pass, not drop).
func newFilterProgram(maxQueues int, matches []Match) (*Program, error) {
	if len(matches) == 0 {
		return nil, fmt.Errorf("afxdp: newFilterProgram needs at least one match")
	}
	for _, m := range matches {
		if m.err != nil {
			return nil, fmt.Errorf("afxdp: filter: %w", m.err)
		}
	}

	// If no match can redirect (e.g. only MatchNone), emit a minimal program
	// that passes everything. It still attaches — enabling zero-copy on the
	// driver for a transmit-only program — but redirects nothing and needs no
	// maps. (A redirect block with nothing jumping to it is unreachable code,
	// which the verifier rejects.)
	anyRedirect := false
	for _, m := range matches {
		if !m.passOnly {
			anyRedirect = true
			break
		}
	}
	if !anyRedirect {
		prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         "xsk_pass",
			Type:         ebpf.XDP,
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, xdpPass), asm.Return()},
			License:      "LGPL-2.1 or BSD-2-Clause",
		})
		if err != nil {
			return nil, fmt.Errorf("afxdp: load pass-only XDP program: %w", err)
		}
		return &Program{Program: prog}, nil // no maps: nothing is redirected
	}
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

	// r6 = data_end, r7 = data, r8 = rx_queue_index (callee-saved across the
	// map_lookup_elem call in the redirect tail).
	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 4, asm.Word),
		asm.LoadMem(asm.R7, asm.R1, 0, asm.Word),
		asm.LoadMem(asm.R8, asm.R1, 16, asm.Word),
	}
	for i, m := range matches {
		entry := fmt.Sprintf("match%d", i)
		next := "pass"
		if i+1 < len(matches) {
			next = fmt.Sprintf("match%d", i+1)
		}
		insns = append(insns, m.build(entry, next, "redirect")...)
	}
	insns = append(insns,
		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("pass"),
		asm.Return(),

		asm.StoreMem(asm.RFP, -4, asm.R8, asm.Word).WithSymbol("redirect"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, qidconf.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "pass"),
		asm.LoadMapPtr(asm.R1, xsks.FD()),
		asm.Mov.Reg(asm.R2, asm.R8),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRedirectMap.Call(),
		asm.Return(),
	)

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "xsk_filter",
		Type:         ebpf.XDP,
		Instructions: insns,
		License:      "LGPL-2.1 or BSD-2-Clause",
	})
	if err != nil {
		qidconf.Close()
		xsks.Close()
		return nil, fmt.Errorf("afxdp: load filter XDP program: %w", err)
	}
	return &Program{Program: prog, Queues: qidconf, Sockets: xsks}, nil
}
