//go:build linux

// tcpsyn captures TCP connection openers — SYN set, ACK clear — which is what
// you want for spotting scans or counting inbound connection attempts without
// taking the established traffic with them.
//
//	go build -o tcpsyn ./examples/customfilter/tcpsyn
//	sudo ./tcpsyn -iface eth0
//
// This one shows a *masked* compare. Every built-in matcher tests a field for
// equality; TCP flags need "these bits set, those bits clear", which is an AND
// followed by a compare. It is also the cheapest custom match to write, because
// the flags are a single byte and single bytes need no byte swapping.
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

// TCP flag bits, as they sit in the single byte at offset 13 of the TCP header.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// matchTCPFlags matches IPv4/TCP packets whose flags byte, masked with mask,
// equals value. matchTCPFlags(tcpSYN|tcpACK, tcpSYN) is "SYN set, ACK clear",
// i.e. a connection opener rather than the reply to one.
//
// The flags byte is at 47: 14 Ethernet + 20 IPv4 (no options) + 13 into the TCP
// header.
func matchTCPFlags(mask, value byte) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("tcp-flags/%#02x=%#02x", mask, value), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, 47+1)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 6, e.Next), // TCP
			asm.LoadMem(asm.R3, frame, 47, asm.Byte),
			asm.And.Imm(asm.R3, int32(mask)),
			asm.JEq.Imm(asm.R3, int32(value), e.Redirect),
		), nil
	})
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	includeSynAck := flag.Bool("synack", false, "also capture SYN+ACK replies")
	flag.Parse()

	// Two matches ORed: WithFilter redirects a packet matching any of them.
	matches := []afxdp.Match{matchTCPFlags(tcpSYN|tcpACK, tcpSYN)}
	if *includeSynAck {
		matches = append(matches, matchTCPFlags(tcpSYN|tcpACK, tcpSYN|tcpACK))
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matches...),
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

// summary decodes who is connecting to what, and which flags were set.
func summary(f []byte) string {
	l3 := 14
	if len(f) >= 14 && binary.BigEndian.Uint16(f[12:]) == afxdp.EtherTypeVLAN {
		l3 = 18
	}
	if len(f) < l3+34 {
		return fmt.Sprintf("%d bytes (short)", len(f))
	}
	src := net.IP(f[l3+12 : l3+16])
	dst := net.IP(f[l3+16 : l3+20])
	sport := binary.BigEndian.Uint16(f[l3+20:])
	dport := binary.BigEndian.Uint16(f[l3+22:])
	return fmt.Sprintf("%4d bytes  %s:%d -> %s:%d  [%s]",
		len(f), src, sport, dst, dport, flagString(f[l3+33]))
}

func flagString(b byte) string {
	s := ""
	for _, f := range []struct {
		bit  byte
		name string
	}{{tcpSYN, "SYN"}, {tcpACK, "ACK"}, {tcpFIN, "FIN"}, {tcpRST, "RST"}, {tcpPSH, "PSH"}} {
		if b&f.bit != 0 {
			if s != "" {
				s += ","
			}
			s += f.name
		}
	}
	return s
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
