//go:build linux

// Copyright 2026 Andree Toonk. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package afxdp

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// Well-known EtherTypes, in their usual host-order values, for use with
// NetShort when comparing the EtherType field of a frame.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
	EtherTypeARP  = 0x0806
	EtherTypeVLAN = 0x8100
)

// OffEtherType is the offset of the EtherType field from the frame base
// returned by MatchEnv.FrameBase. The Ethernet header is dst MAC (6 bytes),
// src MAC (6 bytes), EtherType (2 bytes); L3 payload starts at offset 14.
const OffEtherType = offEtherType

// NetShort returns the network-byte-order (big-endian) value of a 16-bit field
// as a little-endian load sees it, so it can be compared against a u16 loaded
// from the packet with asm.Half. Use it for ports and EtherTypes alike, and for
// any mask applied to such a field:
//
//	asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next)
//
// eBPF loads use the host's byte order, so this is a byte swap on a
// little-endian host and the identity on a big-endian one.
func NetShort(v uint16) int32 { return netshort(v) }

// MatchEnv is passed to a custom match builder (see NewMatch). It carries the
// jump targets the block must use and the registers holding the packet bounds.
//
// The register contract for a custom block:
//
//	R6      data_end (MatchEnv.DataEnd)   read-only
//	R7      frame start (MatchEnv.Data)   read-only
//	R8      rx_queue_index                RESERVED — must not be referenced
//	R9      the FrameBase register        yours once FrameBase has been called
//	R0-R5   scratch                       freely yours
//
// R8 carries the queue the packet arrived on, which the redirect tail reads to
// pick the destination socket. A block that overwrote it would load and verify
// cleanly and then deliver packets to the wrong queue's socket — silently, at
// line rate. Rather than rely on that being remembered, NewMatch rejects any
// block that mentions R8 at all, so the mistake surfaces as an error from Open.
//
// R0-R5 are freely yours — there is no need to look further afield for scratch
// space. The only rule is ordering: the helpers (Bounds, FrameBase) use some of
// them internally, and exactly which is deliberately not part of this contract,
// so load what you need *after* your last helper call rather than before it.
type MatchEnv struct {
	// Next is the symbol to jump to when the packet does NOT match this rule
	// (evaluation continues with the next rule, or the packet is passed to the
	// kernel if this was the last one). Reaching the end of the block without
	// jumping is equivalent: NewMatch appends a jump to Next after the
	// builder's instructions, so ordinary fall-through means "no match".
	Next string
	// Redirect is the symbol to jump to when the packet DOES match. The
	// packet is then redirected to the AF_XDP socket for its queue.
	Redirect string
	// Data holds the address of the first byte of the frame, exactly as the
	// XDP program received it (any VLAN tag included). Treat as read-only;
	// use FrameBase for a base register you can work from.
	Data asm.Register
	// DataEnd holds the address one past the last readable byte. Treat as
	// read-only. Every packet load must be bounds-checked against it first —
	// use Bounds; the verifier rejects an unchecked load outright.
	//
	// With WithMultiBuffer (xdp.frags) DataEnd covers only the first fragment.
	// A read past it still loads fine, it just never passes its bounds check
	// on a fragmented packet, so the match silently stops firing. Keep reads
	// within the L2/L3/L4 headers, which always live in the first fragment.
	DataEnd asm.Register

	// prefix is the block's entry symbol, used to derive collision-free
	// labels. Unexported so MatchEnv values only come from the library.
	prefix string
}

// FrameBase emits the instructions that set a register to the base of the
// Ethernet frame with a single 802.1Q VLAN tag transparently skipped, and
// returns that register. Field offsets relative to it (EtherType at
// OffEtherType, L3 header at 14, ...) resolve the same whether the frame
// reaches XDP tagged or already stripped by the NIC, which is how the built-in
// matchers behave. It bounds-checks its own EtherType read and jumps to Next
// on a runt frame, so the returned instructions are safe to use as the start
// of a block.
//
// Note this is a frame base with a tag stepped over, not a pointer to the L3
// header: on an untagged frame it is Data, on a tagged frame Data+4. The MAC
// addresses and the VLAN tag itself are therefore NOT at their usual offsets
// from it — read those from Data instead.
//
// Call it at most once per block; a second call emits a duplicate symbol and
// Open fails with a duplicate-symbol error. The returned register is owned by
// the block from here on.
func (e MatchEnv) FrameBase() (asm.Instructions, asm.Register) {
	return l3Base(e.prefix+"_fb", e.Next), asm.R9
}

// Bounds emits "if base + n > data_end, jump to Next", bounds-checking a read
// of the first n bytes starting at base. The eBPF verifier rejects any packet
// load that is not preceded by such a check.
func (e MatchEnv) Bounds(base asm.Register, n int32) asm.Instructions {
	return boundsFrom(base, n, e.Next)
}

// Label returns a symbol name unique to this block, for custom control flow
// (e.g. a landing pad inside the block). name must be unique within the block.
func (e MatchEnv) Label(name string) string {
	return e.prefix + "_u_" + name
}

// checkBlock rejects a classification block that violates the register
// contract. Both rules exist because breaking them is silent: the program
// loads, verifies, attaches, and then quietly does the wrong thing at line
// rate. Documenting them was not enough.
//
// R8 (rx_queue_index) may not be mentioned at all, as Dst or as Src. The
// redirect tail reads it to choose the destination socket, so a block that
// overwrites it delivers packets to another queue's socket. Reads are rejected
// along with writes because telling them apart means modelling per-opcode
// operand semantics, and no block has a reason to read the queue index yet;
// being strict keeps the check honest as instruction forms are added.
//
// R6 (data_end) and R7 (data) may not be *written*, but are freely read —
// reading them is the entire point of MatchEnv, and FrameBase and Bounds emit
// such reads themselves. A block that moves R7 leaves every later block in the
// filter, including the built-in matchers and the WithKeepManagement
// exceptions, parsing at the wrong offset. "Written" is decided per opcode
// class: ALU and load instructions write their Dst; conditional jumps and
// stores only read it (a jump compares Dst, a store uses Dst as the address
// base), so R6/R7 as the left operand of a comparison is legal.
//
// A block also may not return an XDP action of its own. Doing so loads happily
// and turns the filter into a dropper: with any exception present the program
// returns that action for every packet reaching the block, so a stray Return()
// silently overrides WithKeepManagement and can take the box off the network.
// In any other position it orphans the blocks after it and the verifier reports
// "unreachable insn" against an instruction the user never wrote. A block
// decides by jumping to Next or Redirect; the tails decide the action.
//
// The register scan assumes registers appear only in an instruction's Dst and
// Src, which holds for github.com/cilium/ebpf/asm: its encoder packs registers
// from exactly those two fields, and the one multi-word form (LdImmDW) carries
// no register in its second word. Recheck this if that dependency changes.
//
// Reported indices are into the emitted block, which for a custom match can be
// offset by one from what the builder returned (NewMatch prepends a filler
// instruction when the builder labelled its own first instruction). The
// disassembly in the message identifies the instruction unambiguously.
func checkBlock(ins asm.Instructions) error {
	for i, in := range ins {
		var why string
		switch {
		case in.Dst == asm.R8 || in.Src == asm.R8:
			why = "references R8, which is reserved for rx_queue_index; " +
				"use R0-R5 as scratch, or the register FrameBase returns"
		case in.Dst == asm.R6 && writesDst(in.OpCode):
			why = "writes R6, which holds data_end and is read-only"
		case in.Dst == asm.R7 && writesDst(in.OpCode):
			why = "writes R7, which holds the frame start and is read-only; " +
				"use FrameBase for a base register you can work from"
		case in.OpCode.Class().IsJump() && in.OpCode.JumpOp() == asm.Exit:
			why = "returns an XDP action; a match block must jump to " +
				"env.Redirect or env.Next and let the filter choose the action"
		default:
			continue
		}
		return fmt.Errorf("instruction %d (%v) %s", i, in, why)
	}
	return nil
}

// writesDst reports whether an instruction of this opcode class writes its Dst
// register. ALU/ALU64 (including endianness conversions) and the load classes
// do; jumps read Dst as the left comparison operand, and stores read it as the
// memory address base.
func writesDst(op asm.OpCode) bool {
	switch op.Class() {
	case asm.LdClass, asm.LdXClass, asm.ALUClass, asm.ALU64Class:
		return true
	}
	return false
}

// terminates reports whether ins ends in an unconditional jump, which cannot
// fall through and so must not have a jump appended after it (the extra
// instruction would be unreachable, which the verifier rejects). Conditional
// jumps do fall through and so do not count. A trailing Exit would also not
// fall through, but checkBlock rejects those outright.
func terminates(ins asm.Instructions) bool {
	if len(ins) == 0 {
		return false
	}
	op := ins[len(ins)-1].OpCode
	return op.Class().IsJump() && op.JumpOp() == asm.Ja
}

// MatchError returns a Match that makes Open fail with err. It is the way a
// custom matcher constructor reports invalid arguments, mirroring what the
// built-in builders do internally: return a Match rather than an error, and let
// Open surface the problem.
//
//	func MatchSrcMAC(s string) afxdp.Match {
//		mac, err := net.ParseMAC(s)
//		if err != nil {
//			return afxdp.MatchError("src-mac(invalid)", err)
//		}
//		if len(mac) != 6 {
//			return afxdp.MatchError("src-mac(invalid)",
//				fmt.Errorf("need a 6-byte Ethernet address, got %d bytes", len(mac)))
//		}
//		return afxdp.NewMatch("src-mac/"+mac.String(), func(e afxdp.MatchEnv) (asm.Instructions, error) {
//			...
//		})
//	}
//
// desc is what Fleet.Info would have reported; it appears in the error message.
func MatchError(desc string, err error) Match {
	if err == nil {
		err = errors.New("invalid match")
	}
	return Match{desc: desc, err: err}
}

// NewMatch returns a custom Match for WithFilter, classifying packets with
// caller-supplied eBPF. desc is the short human-readable summary reported by
// Fleet.Info (e.g. "udp/5000"). build must return the instructions for one
// classification block: jump to env.Redirect on a match, jump to env.Next (or
// simply fall through) otherwise. A builder that cannot fail returns a nil
// error; one that compiles something (see the bpfmatch module, which compiles
// classic BPF) reports the failure and Open surfaces it. See MatchEnv for the register contract — in
// particular, R8 is reserved and a block that mentions it is rejected.
//
// build is called while Open assembles the filter program, and may be called
// more than once for a single Open: each attach mode Open tries (native, then
// generic) reassembles the program. It must therefore be deterministic and free
// of side effects — do not count invocations, mutate captured state, or use
// sync.Once inside it.
//
// To reject bad arguments, return MatchError instead of calling NewMatch.
//
// A typical block starts with env.FrameBase, bounds-checks with env.Bounds,
// then loads and compares header fields:
//
//	udp5000 := afxdp.NewMatch("udp/5000", func(e afxdp.MatchEnv) (asm.Instructions, error) {
//		ins, frame := e.FrameBase()
//		// Ethernet 14 + IPv4 20 (no options) puts the UDP dst port at 36.
//		ins = append(ins, e.Bounds(frame, 36+2)...)
//		return append(ins,
//			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
//			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
//			asm.LoadMem(asm.R3, frame, 23, asm.Byte), // IP protocol
//			asm.JNE.Imm(asm.R3, 17, e.Next),          // UDP
//			asm.LoadMem(asm.R3, frame, 36, asm.Half), // UDP dst port
//			asm.JEq.Imm(asm.R3, afxdp.NetShort(5000), e.Redirect),
//		), nil
//	})
//
// Mistakes in the instructions surface from Open as an *ebpf.VerifierError.
// Printing it with %v gives only its first line; use errors.As and %+v to get
// the program listing that shows which instruction the verifier rejected. One
// failure is worth knowing in advance: if no match in the filter ever jumps to
// Redirect, the redirect path is unreachable code and the verifier rejects the
// whole program with "unreachable insn".
func NewMatch(desc string, build func(MatchEnv) (asm.Instructions, error)) Match {
	if build == nil {
		return Match{desc: desc, err: errors.New("NewMatch called with a nil build func")}
	}
	return Match{desc: desc, build: func(entry, next, redirect string) (asm.Instructions, error) {
		ins, err := build(MatchEnv{
			Next:     next,
			Redirect: redirect,
			Data:     asm.R7,
			DataEnd:  asm.R6,
			prefix:   entry,
		})
		if err != nil {
			return nil, err
		}
		// Make fall-through explicit so a custom block never depends on the
		// physical layout of the blocks around it. Skipped when the block
		// already ends in an unconditional jump: the extra instruction would
		// be unreachable, which the verifier rejects.
		if !terminates(ins) {
			ins = append(ins, asm.Ja.Label(next))
		}
		// The entry symbol goes on the block's first instruction. If the
		// builder already put its own symbol there (a loop label, say),
		// prepend a filler instruction to carry the entry symbol rather than
		// overwriting theirs — otherwise their label vanishes and any jump to
		// it fails at load time with "unsatisfied program reference".
		//
		// The filler writes a scratch register with a constant: it must not
		// *read* any register, since nothing but R6/R7/R8 is initialised at
		// block entry and the verifier rejects a read of the rest.
		if ins[0].Symbol() != "" {
			ins = append(asm.Instructions{asm.Mov.Imm(asm.R0, 0)}, ins...)
		}
		return withEntry(entry, ins), nil
	}}
}
