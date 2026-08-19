//go:build linux

// Copyright 2026 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package bpfmatch matches packets with classic BPF (cBPF) — the instruction
// set tcpdump and libpcap compile filter expressions to.
//
//	fleet, err := afxdp.Open("eth0", afxdp.WithFilter(
//		bpfmatch.Match("ssh, not from .1", insns),
//	))
//
// It is a separate Go module so that the compiler it depends on
// (github.com/cloudflare/cbpfc) and the Go and cilium/ebpf versions that
// compiler requires do not reach anyone who only uses go-afxdp's built-in
// matchers:
//
//	go get github.com/atoonk/go-afxdp/bpfmatch
//
// It is still pure Go. For filter *expressions* rather than instructions, see
// github.com/atoonk/go-afxdp/pcapfilter, which needs libpcap.
package bpfmatch

import (
	"errors"
	"fmt"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

// Match matches packets accepted by a classic BPF (cBPF) program — the
// instruction set tcpdump and libpcap compile their filter expressions to. It
// is the general-purpose filter layer: any packet-data filter tcpdump can
// express, this can match, including the things the named builders cannot.
// (The one exclusion is programs using Linux ancillary loads — see below.)
//
//	// tcpdump -ddd 'tcp port 22 and not src host 192.0.2.1', or
//	// pcap.CompileBPFFilter, or any other cBPF source
//	fleet, err := afxdp.Open("eth0", afxdp.WithFilter(
//		bpfmatch.Match("tcp/22 inbound", insns),
//	))
//
// The program is compiled to eBPF and spliced into the filter alongside every
// other match, so it composes with the named builders, with other bpfmatch
// matches, and with WithKeepManagement exactly as they compose with each other.
// A packet is redirected if the program accepts it (returns non-zero).
//
// Semantics are exactly those of the supplied cBPF program, evaluated against
// the frame as XDP received it:
//
//   - Offsets are from the start of the Ethernet frame. Unlike the named
//     builders, no VLAN tag is stepped over for you — a pcap-compiled filter
//     handles tags itself, which is why "vlan 100 and tcp port 22" works and
//     matches only tagged frames.
//
//   - Variable-length IPv4 headers are handled if the program handles them,
//     which pcap-compiled programs do. This is the one filter layer here that
//     matches IPv4 packets carrying options.
//
//   - IPv6 extension headers follow libpcap's behaviour: a filter naming an L4
//     port does not match a packet whose L4 header sits behind an extension
//     header chain.
//
//   - Length tests ("greater 100", "len > 500") compare against the bytes XDP
//     can see. With WithMultiBuffer that is the first fragment, not the whole
//     frame, so such a filter under-reports on a jumbo packet.
//
// XDP is ingress-only, so a filter written expecting to see both directions of
// a conversation only ever sees the inbound half.
//
// Compile expressions against a *dead* pcap handle (pcap.OpenDead, which is
// what gopacket's pcap.CompileBPFFilter and "tcpdump -ddd" use). Compiling
// against a live handle lets libpcap emit Linux ancillary loads — negative
// offsets such as SKF_AD_VLAN_TAG_PRESENT — which read socket-buffer metadata
// that does not exist in XDP. Those are rejected rather than silently wrong,
// but the error names an offset you never wrote.
//
// A program that cannot be compiled — malformed, or reaching past the 64KB
// maximum packet offset — is reported by Open rather than attached, naming this
// match. A program that compiles but that the kernel verifier then rejects
// produces a whole-program error which cannot be attributed back to one block;
// with several matches installed you may have to bisect.
func Match(desc string, filter []bpf.Instruction) afxdp.Match {
	if len(filter) == 0 {
		return afxdp.MatchError(desc, errors.New("bpfmatch.Match needs at least one cBPF instruction"))
	}
	if desc == "" {
		desc = fmt.Sprintf("bpf(%d insns)", len(filter))
	}
	// Decode any raw instructions. "tcpdump -ddd" and pcap_compile both produce
	// the packed form, and x/net/bpf models it as bpf.RawInstruction, which the
	// compiler below does not accept — so normalise here rather than making
	// every caller remember to Disassemble.
	prog := make([]bpf.Instruction, len(filter))
	for i, in := range filter {
		if raw, ok := in.(bpf.RawInstruction); ok {
			prog[i] = raw.Disassemble()
			// Disassemble returns the RawInstruction unchanged when the opcode
			// is not one it knows. Nothing downstream can use that.
			if _, still := prog[i].(bpf.RawInstruction); still {
				return afxdp.MatchError(desc, fmt.Errorf("instruction %d: unrecognised cBPF opcode %#x", i, raw.Op))
			}
			continue
		}
		prog[i] = in
	}
	return afxdp.NewMatch(desc, func(e afxdp.MatchEnv) (asm.Instructions, error) {
		result := e.Label("bpf_result")
		ins, err := cbpfc.ToEBPF(prog, cbpfc.EBPFOpts{
			// cbpfc documents both of these as "Not modified", which is what
			// lets a generated block satisfy the read-only R6/R7 rule.
			PacketStart: e.Data,
			PacketEnd:   e.DataEnd,
			// cBPF offsets are from the frame start, so no adjustment.
			PacketStartMaxOffset: 0,
			Result:               asm.R0,
			ResultLabel:          result,
			// Scratch registers are ours to pick, which is how a generated
			// block avoids R8 without cbpfc knowing anything about it.
			Working: [4]asm.Register{asm.R1, asm.R2, asm.R3, asm.R4},
			// Derived from this block's entry symbol, so two bpfmatch matches
			// in one filter cannot collide.
			LabelPrefix: e.Label("bpf"),
		})
		if err != nil {
			return nil, fmt.Errorf("compiling cBPF to eBPF: %w", err)
		}
		// cbpfc jumps to ResultLabel with the filter's return value in Result.
		// Non-zero means the cBPF program accepted the packet.
		return append(ins,
			asm.JNE.Imm(asm.R0, 0, e.Redirect).WithSymbol(result),
		), nil
	})
}
