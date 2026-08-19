//go:build linux

// Copyright 2026 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package pcapfilter compiles tcpdump filter expressions into afxdp matches.
//
//	fleet, err := afxdp.Open("eth0", afxdp.WithFilter(
//		pcapfilter.Match("tcp port 22 and not src host 192.0.2.1"),
//	))
//
// It is a separate Go module on purpose. Expression parsing needs libpcap,
// which needs cgo, and go-afxdp itself is pure Go — so this dependency is
// opt-in and never reaches anyone who does not import this package:
//
//	go get github.com/atoonk/go-afxdp/pcapfilter
//
// You will need libpcap's headers (libpcap-dev on Debian/Ubuntu,
// libpcap-devel on Fedora) to build it.
//
// The expression is compiled to classic BPF by libpcap and handed to
// bpfmatch.Match, so semantics are exactly tcpdump's — including
// variable-length IPv4 headers and its VLAN handling. XDP is ingress-only, so
// a filter written expecting both directions only sees the inbound half.
package pcapfilter

import (
	"fmt"

	"github.com/atoonk/go-afxdp"
	"github.com/atoonk/go-afxdp/bpfmatch"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// snapLen is the capture length libpcap compiles against. Filters that slice
// into the packet are bounded by it, so it is set to the largest frame an
// afxdp socket can deliver rather than a typical MTU.
const snapLen = 65535

// linkTypeEthernet is DLT_EN10MB from libpcap's pcap/dlt.h — the link type for
// Ethernet, which is what XDP delivers. Spelled out here rather than imported
// from gopacket's layers package, which is large and would be pulled in for
// this one integer.
const linkTypeEthernet = 1

// Match compiles a tcpdump filter expression into an afxdp.Match.
//
// A bad expression is carried in the returned Match and reported by Open,
// which is the same contract the built-in builders follow (afxdp.MatchSrcIP
// with a bad CIDR behaves the same way). That keeps it usable inline:
//
//	fleet, err := afxdp.Open("eth0", afxdp.WithFilter(
//		pcapfilter.Match("tcp port 22 and not src host 192.0.2.1"),
//	))
//
// Use Compile if you would rather see the error at the point of compilation.
func Match(expr string) afxdp.Match {
	m, _ := Compile(expr)
	return m
}

// Compile is Match with the compile error returned as well, for callers
// validating an expression before they open anything.
func Compile(expr string) (afxdp.Match, error) {
	insns, err := pcap.CompileBPFFilter(linkTypeEthernet, snapLen, expr)
	if err != nil {
		e := fmt.Errorf("compiling %q: %w", expr, err)
		return afxdp.MatchError(expr, e), e
	}
	// bpfmatch.Match decodes the packed form itself.
	prog := make([]bpf.Instruction, len(insns))
	for i, in := range insns {
		prog[i] = bpf.RawInstruction{Op: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	return bpfmatch.Match(expr, prog), nil
}
