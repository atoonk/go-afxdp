//go:build linux

// udpsrcport is the simplest NewMatch example, and the one to read first. It
// captures IPv4/UDP traffic by source port.
//
//	go build -o udpsrcport ./examples/customfilter/udpsrcport
//	sudo ./udpsrcport -iface eth0 -port 12345
//
// If source-port matching is what you actually want, do NOT copy this: use the
// built-in, which also covers IPv6 and is a single line.
//
//	afxdp.Open("eth0", afxdp.WithFilter(afxdp.MatchUDPSrcPort(12345)))
//
// This exists to show the shape of a custom match on a filter simple enough to
// check by eye — bounds-check, load, compare — before you read the ones that do
// something the built-ins cannot. The whole matcher is six instructions, and
// the only difference from the built-in MatchUDPPort is one offset: the UDP
// source port is at 34 where the destination port is at 36.
//
// If neither the built-ins nor a tcpdump expression (see the pcapfilter module)
// covers your case, that is when to write one of these.
//
// The default port is deliberately a harmless high one. Capturing source port
// 53 on the interface you administer the box through would take the kernel's
// own DNS replies away from it and break name resolution while this runs —
// which is exactly what WithKeepManagement below prevents, by keeping DNS
// replies addressed to this host with the kernel. That also means -port 53
// here shows you other hosts' DNS replies (on a mirror port, say), not your
// own.
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

// matchUDPSrcPort matches IPv4/UDP packets whose source port is port. The
// built-in afxdp.MatchUDPSrcPort does this for both address families; this is
// the hand-written version, for illustration.
//
// Offsets are relative to the frame base returned by FrameBase, which has any
// VLAN tag already stepped over: EtherType at 12, IP protocol at 23 (14 + 9),
// and the UDP source port at 34 (14 + 20 + 0). The 14 + 20 assumes an IPv4
// header with no options, which is what the built-in matchers assume too.
func matchUDPSrcPort(port uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("udp-src/%d", port), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		// One bounds check covering the furthest byte we read (34+2) is enough;
		// the verifier rejects any load not covered by one.
		ins = append(ins, e.Bounds(frame, 34+2)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next), // UDP
			asm.LoadMem(asm.R3, frame, 34, asm.Half),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(port), e.Redirect),
		), nil
	})
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	port := flag.Uint("port", 12345, "UDP source port to capture")
	flag.Parse()

	if *port > 65535 {
		log.Fatalf("port %d out of range", *port)
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matchUDPSrcPort(uint16(*port))),
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

// summary prints the flow, so you can confirm the source port is the one asked
// for and watch which hosts it is coming from.
func summary(f []byte) string {
	// Skip a VLAN tag here too: XDP saw the frame exactly as it arrived.
	l3 := 14
	if len(f) >= 14 && binary.BigEndian.Uint16(f[12:]) == afxdp.EtherTypeVLAN {
		l3 = 18
	}
	if len(f) < l3+28 {
		return fmt.Sprintf("%d bytes (short)", len(f))
	}
	src := net.IP(f[l3+12 : l3+16])
	dst := net.IP(f[l3+16 : l3+20])
	sport := binary.BigEndian.Uint16(f[l3+20:])
	dport := binary.BigEndian.Uint16(f[l3+22:])
	return fmt.Sprintf("%4d bytes  %s:%d -> %s:%d", len(f), src, sport, dst, dport)
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
