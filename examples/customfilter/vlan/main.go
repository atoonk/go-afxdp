//go:build linux

// vlan captures traffic on one 802.1Q VLAN and prints a line per packet.
//
//	go build -o vlan ./examples/customfilter/vlan
//	sudo ./vlan -iface eth0 -vid 100
//
// There is no built-in MatchVLAN, and the reason is instructive: every built-in
// matcher works from MatchEnv.FrameBase, which deliberately steps over a VLAN
// tag so the same filter matches whether or not the NIC stripped the tag before
// XDP. That is the right default, but it also means the tag is invisible from
// there. To match the tag itself you read from the raw frame start,
// MatchEnv.Data, which is what this example shows.
//
// If this captures nothing, suspect the NIC before the filter. Most drivers
// strip the VLAN tag in hardware before XDP ever sees the frame, in which case
// there is no tag left to match and this matches nothing, silently. Turn the
// offload off first:
//
//	ethtool -K eth0 rxvlan off
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// matchVLAN matches frames carrying an 802.1Q tag with the given VLAN ID.
//
// The 4-byte tag sits between the source MAC and the EtherType: a 2-byte TPID
// of 0x8100 at offset 12, then a 2-byte TCI at 14 whose low 12 bits are the
// VLAN ID. Both are big-endian on the wire while eBPF loads little-endian, so
// the mask and the value both go through NetShort.
func matchVLAN(vid uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("vlan/%d", vid), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		// Read from e.Data, not FrameBase: FrameBase would have skipped the
		// very tag we are trying to inspect.
		ins := e.Bounds(e.Data, 16)
		return append(ins,
			asm.LoadMem(asm.R3, e.Data, 12, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeVLAN), e.Next),
			asm.LoadMem(asm.R3, e.Data, 14, asm.Half),
			asm.And.Imm(asm.R3, afxdp.NetShort(0x0fff)),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(vid), e.Redirect),
		), nil
	})
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	vid := flag.Uint("vid", 100, "VLAN ID to capture")
	flag.Parse()

	if *vid < 1 || *vid > 4094 {
		log.Fatalf("vid %d out of range (1-4094)", *vid)
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matchVLAN(uint16(*vid))),
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

// summary decodes the tag the filter matched on, so you can see it agreeing.
func summary(f []byte) string {
	if len(f) < 18 {
		return fmt.Sprintf("%d bytes (runt)", len(f))
	}
	tci := uint16(f[14])<<8 | uint16(f[15])
	inner := uint16(f[16])<<8 | uint16(f[17])
	return fmt.Sprintf("%4d bytes  vlan=%-4d pcp=%d  inner ethertype=0x%04x",
		len(f), tci&0x0fff, tci>>13, inner)
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
