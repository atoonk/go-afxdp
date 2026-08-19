//go:build linux

// Copyright 2026 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// xdpTx is the sentinel action matchPacket places at the "redirect" label so
// BPF_PROG_TEST_RUN can tell a match from a non-match. The real redirect tail
// cannot be exercised this way: its qidconf gate reads a map with no queues
// registered and always falls through to pass.
const xdpTx = 3

// MatchPacket reports whether pkt would be redirected by a filter configured
// with the given options, which are the same options Open takes:
//
//	ok, err := afxdp.MatchPacket(frame,
//		afxdp.WithFilter(myMatch),
//		afxdp.WithExcept(afxdp.MatchSrcIP("192.0.2.10/32")),
//	)
//
// It is a testing aid. It builds the same classification blocks Open would
// attach — from the same configuration, through the same validation — and runs
// them in the kernel with BPF_PROG_TEST_RUN against pkt. It does not
// reimplement matching in Go, so a wrong offset, a missing byte swap, the wrong
// protocol number or a mishandled VLAN tag shows up here exactly as it would on
// a live interface. That makes a filter unit-testable with no NIC and no
// traffic.
//
// Test the near misses too. A byte-order slip typically still matches
// something, so a matcher that only ever sees packets it should accept looks
// correct right up until it is deployed.
//
// Distinguish the two kinds of error, and do not simply skip on any of them.
// The kernel reports a verifier rejection as EACCES, so a broken matcher and a
// missing capability both arrive as "permission denied" and `err != nil` alone
// cannot tell them apart. A verifier rejection unwraps to *ebpf.VerifierError
// and means the filter is wrong, which is a test failure; anything else means
// this machine cannot run the check, which is a skip:
//
//	ok, err := afxdp.MatchPacket(frame, afxdp.WithFilter(myMatch))
//	if err != nil {
//		var ve *ebpf.VerifierError
//		if errors.As(err, &ve) {
//			t.Fatalf("filter rejected:\n%+v", ve) // the filter is broken
//		}
//		t.Skipf("cannot run BPF here: %v", err) // no privileges, no BPF
//	}
//
// Requirements and limits:
//
//   - It loads and runs a BPF program, so it needs the same privileges Open
//     does (CAP_BPF and CAP_NET_ADMIN, or root) plus locked-memory headroom.
//     A test binary usually needs rlimit.RemoveMemlock() from
//     github.com/cilium/ebpf/rlimit before the first call.
//   - The kernel requires pkt to be at least 14 bytes for an XDP test run.
//   - Only classification is exercised. The redirect tail that picks the
//     destination socket for a queue is not, so this cannot tell you whether a
//     packet ends up on the queue you expect — only whether it is selected.
//   - WithKeepManagement has no interface to read addresses from here, so it
//     expands to the unscoped rules (any destination) that Open falls back to
//     when an interface's addresses cannot be determined. That is wider than
//     what Open installs when it does know them.
//   - WithMultiBuffer is honoured: the test program is loaded with
//     BPF_F_XDP_HAS_FRAGS, exactly as Open would load it, so a filter that
//     only verifies without the flag (or only with it) is caught here.
//   - Options unrelated to filtering (queue counts, frame sizes, XDP mode) are
//     accepted and ignored.
func MatchPacket(pkt []byte, opts ...Option) (bool, error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	exceptions := cfg.except
	if cfg.keepManagement {
		// No interface here, so use the fail-safe unscoped form.
		exceptions = append(managementExceptions(nil, cfg.mgmtTCPPorts, true), exceptions...)
	}
	return matchPacket(exceptions, cfg.matches, pkt, cfg.multiBuffer)
}

// matchPacket assembles and runs the classifier for one exception/match set.
// frags loads the program with BPF_F_XDP_HAS_FRAGS, as WithMultiBuffer does.
func matchPacket(exceptions, matches []Match, pkt []byte, frags bool) (bool, error) {
	if len(matches) == 0 {
		return false, fmt.Errorf("afxdp: MatchPacket needs a filter (pass WithFilter)")
	}
	// The kernel returns a bare EINVAL for a short XDP test packet; say why.
	if len(pkt) < 14 {
		return false, fmt.Errorf("afxdp: MatchPacket needs at least 14 bytes of "+
			"packet (an Ethernet header), got %d", len(pkt))
	}
	blocks, err := classifierBlocks(exceptions, matches)
	if err != nil {
		return false, err
	}

	insns := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 4, asm.Word),
		asm.LoadMem(asm.R7, asm.R1, 0, asm.Word),
		asm.LoadMem(asm.R8, asm.R1, 16, asm.Word),
		// Two edges that are never taken, so both tails stay reachable however
		// the blocks jump. Without them a filter whose blocks always redirect
		// (MatchAll alone) orphans the pass tail, and one that never redirects
		// (MatchNone alone) orphans the redirect tail, and the verifier
		// rejects a filter that Open would have accepted. Reachability is
		// computed before value tracking, so the edges cost nothing at run
		// time.
		asm.Mov.Imm(asm.R0, 1),
		asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.JEq.Imm(asm.R0, 0, "redirect"),
	}
	insns = append(insns, blocks...)
	insns = append(insns,
		asm.Mov.Imm(asm.R0, xdpPass).WithSymbol("pass"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, xdpTx).WithSymbol("redirect"),
		asm.Return(),
	)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "xsk_matchpkt",
		Type:         ebpf.XDP,
		Flags:        fragsFlag(frags),
		Instructions: insns,
		License:      "LGPL-2.1 or BSD-2-Clause",
	})
	if err != nil {
		return false, fmt.Errorf("afxdp: load filter for MatchPacket: %w", err)
	}
	defer prog.Close()

	ret, _, err := prog.Test(pkt)
	if err != nil {
		return false, fmt.Errorf("afxdp: run filter for MatchPacket: %w", err)
	}
	switch ret {
	case xdpTx:
		return true, nil
	case xdpPass:
		return false, nil
	}
	return false, fmt.Errorf("afxdp: MatchPacket: filter returned unexpected action %d", ret)
}
