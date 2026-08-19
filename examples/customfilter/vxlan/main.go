//go:build linux

// vxlan captures one VXLAN tunnel by VNI and prints the inner frame.
//
//	go build -o vxlan ./examples/customfilter/vxlan
//	sudo ./vxlan -iface eth0 -vni 1234
//
// This is the example most likely to match a real problem. WithUDPPorts(4789)
// gets you every VXLAN tunnel on the wire, which on a busy host is a lot of
// traffic to drag into userspace only to throw most of it away. Narrowing to a
// single VNI in the kernel means the rest never leaves the NIC's queue.
//
// It also shows the thing WithFilter cannot express: three conditions ANDed
// together. WithFilter ORs its matches, so "UDP and port 4789 and VNI 1234"
// has to live inside one block — which is exactly what a custom match is.
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

// vniLE byte-swaps a 24-bit VNI so it can be compared against a little-endian
// 32-bit load of the three VNI bytes plus the reserved byte that follows them.
func vniLE(vni uint32) int32 {
	return int32((vni&0xff)<<16 | (vni & 0xff00) | (vni>>16)&0xff)
}

// matchVXLAN matches IPv4/UDP/4789 carrying the given VNI.
//
// Offsets from the frame base: EtherType 12, IP protocol 23, UDP dest port 36,
// and the VXLAN header at 42 (14 Ethernet + 20 IPv4 + 8 UDP). The VXLAN header
// is 1 byte of flags, 3 reserved, then the 3-byte VNI at +4 (so 46) and one
// more reserved byte. There is no 24-bit load, so we load 32 bits and mask the
// trailing reserved byte away.
func matchVXLAN(vni uint32) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("vxlan/%d", vni), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, 46+4)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next), // UDP
			asm.LoadMem(asm.R3, frame, 36, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(4789), e.Next), // VXLAN port
			asm.LoadMem(asm.R3, frame, 46, asm.Word),
			asm.And.Imm(asm.R3, 0x00ffffff),
			asm.JEq.Imm(asm.R3, vniLE(vni), e.Redirect),
		), nil
	})
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	vni := flag.Uint("vni", 1234, "VXLAN VNI to capture")
	flag.Parse()

	if *vni > 0xffffff {
		log.Fatalf("vni %d out of range (24-bit)", *vni)
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matchVXLAN(uint32(*vni))),
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

// summary reports the outer tunnel endpoints and the inner frame's MACs — the
// payoff for filtering on VNI, since the inner frame is what you actually want.
func summary(f []byte) string {
	l3 := 14
	if len(f) >= 14 && binary.BigEndian.Uint16(f[12:]) == afxdp.EtherTypeVLAN {
		l3 = 18
	}
	vx := l3 + 28 // IPv4 20 + UDP 8
	if len(f) < vx+8+14 {
		return fmt.Sprintf("%d bytes (short)", len(f))
	}
	outerSrc := net.IP(f[l3+12 : l3+16])
	outerDst := net.IP(f[l3+16 : l3+20])
	vni := uint32(f[vx+4])<<16 | uint32(f[vx+5])<<8 | uint32(f[vx+6])
	inner := f[vx+8:]
	return fmt.Sprintf("%4d bytes  %s -> %s  vni=%d  inner %s -> %s ethertype=0x%04x",
		len(f), outerSrc, outerDst, vni,
		net.HardwareAddr(inner[6:12]), net.HardwareAddr(inner[0:6]),
		binary.BigEndian.Uint16(inner[12:]))
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
