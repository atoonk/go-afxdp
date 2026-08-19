//go:build linux

// dstmac captures frames addressed to one destination MAC — useful on a mirror
// or SPAN port, where you are seeing another host's traffic and want only the
// part addressed to a particular NIC. Passing a multicast or broadcast address
// works the same way.
//
//	go build -o dstmac ./examples/customfilter/dstmac
//	sudo ./dstmac -iface eth0 -mac aa:bb:cc:dd:ee:ff
//
// Two things worth noticing. eBPF has no 48-bit load, so a 6-byte MAC needs two
// compares: a 32-bit one and a 16-bit one. And like the vlan example this reads
// from MatchEnv.Data rather than FrameBase, because the MACs come *before* any
// VLAN tag — using the VLAN-adjusted base would read four bytes off on a tagged
// frame, which would still verify and still match something.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// matchDstMAC matches frames whose destination MAC is s. The destination MAC
// is the first 6 bytes of the frame, before the source MAC and any VLAN tag.
//
// It validates its own argument and reports a bad one with MatchError, which
// Open surfaces — the same contract the built-in builders follow, and the
// reason this function is safe to lift into your own code as-is. Doing the
// checks here rather than in main also matters because net.ParseMAC accepts
// 8-byte EUI-64 and 20-byte InfiniBand addresses, which would index out of
// range below.
func matchDstMAC(s string) afxdp.Match {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return afxdp.MatchError("dst-mac(invalid)", err)
	}
	if len(mac) != 6 {
		return afxdp.MatchError("dst-mac(invalid)",
			fmt.Errorf("need a 6-byte Ethernet address, got %d bytes from %q", len(mac), s))
	}
	// Little-endian loads see the first byte as least significant, so build the
	// expected values the same way rather than byte-swapping after the fact.
	lo := uint32(mac[0]) | uint32(mac[1])<<8 | uint32(mac[2])<<16 | uint32(mac[3])<<24
	hi := uint32(mac[4]) | uint32(mac[5])<<8
	return afxdp.NewMatch("dst-mac/"+mac.String(), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins := e.Bounds(e.Data, 6)
		return append(ins,
			asm.LoadMem(asm.R3, e.Data, 0, asm.Word),
			// Imm32 compares the low 32 bits, which matters because lo can have
			// its top bit set and a 64-bit compare would disagree.
			asm.JNE.Imm32(asm.R3, int32(lo), e.Next),
			asm.LoadMem(asm.R3, e.Data, 4, asm.Half),
			asm.JEq.Imm(asm.R3, int32(hi), e.Redirect),
		), nil
	})
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	macStr := flag.String("mac", "", "destination MAC to capture (required), e.g. aa:bb:cc:dd:ee:ff")
	flag.Parse()

	if *macStr == "" {
		log.Fatal("-mac is required")
	}

	// No validation here: matchDstMAC checks its own argument and Open reports
	// the problem.
	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matchDstMAC(*macStr)),
		// See the header: keeps your SSH session with the kernel.
		afxdp.WithKeepManagement())
	if err != nil {
		fatalOpen(*iface, err)
	}

	if info, err := fleet.Info(); err == nil {
		log.Printf("started: %s", info)
	}
	log.Printf("waiting for the link to come up...")
	if fleet.WaitLinkUp(15 * time.Second) {
		log.Printf("link up; waiting for matching packets (ctrl-c to stop)")
	} else {
		log.Printf("warning: link not up after 15s; continuing anyway")
	}

	for _, xsk := range fleet.Sockets() {
		go func(xsk *afxdp.Socket) {
			for {
				xsk.Fill(xsk.NumFreeFillSlots())
				n, err := xsk.Poll(-1)
				if err != nil {
					return
				}
				descs := xsk.Receive(n)
				for _, d := range descs {
					fmt.Println(summary(xsk.GetFrame(d)))
				}
				xsk.Recycle(descs)
			}
		}(xsk)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fleet.Close()
	log.Println("stopped")
}

// summary shows both MACs and the EtherType, skipping a VLAN tag if present so
// the reported EtherType is the meaningful inner one.
func summary(f []byte) string {
	if len(f) < 14 {
		return fmt.Sprintf("%d bytes (runt)", len(f))
	}
	et := binary.BigEndian.Uint16(f[12:])
	tag := ""
	if et == afxdp.EtherTypeVLAN && len(f) >= 18 {
		tag = fmt.Sprintf(" vlan=%d", binary.BigEndian.Uint16(f[14:])&0x0fff)
		et = binary.BigEndian.Uint16(f[16:])
	}
	return fmt.Sprintf("%4d bytes  %s -> %s%s  ethertype=0x%04x",
		len(f), net.HardwareAddr(f[6:12]), net.HardwareAddr(f[0:6]), tag, et)
}

// fatalOpen reports an Open failure and exits. A filter the kernel verifier
// rejects arrives as an *ebpf.VerifierError whose %v form is a single line
// ("unreachable insn 6"); the program listing that shows which instruction was
// rejected only appears under %+v, and only if you unwrap to the concrete type.
func fatalOpen(iface string, err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		log.Fatalf("open %s: the filter was rejected by the kernel verifier:\n%+v", iface, ve)
	}
	log.Fatalf("open %s: %v", iface, err)
}
