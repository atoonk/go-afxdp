//go:build linux

// This example captures traffic with a tcpdump filter expression — the whole
// point of the pcapfilter module.
//
//	cd pcapfilter && go build -o tcpdumpfilter ./example
//	sudo ./tcpdumpfilter -iface eth0 -filter "tcp port 443 and not src net 192.0.2.0/24"
//
// The expression is compiled by libpcap exactly as tcpdump would compile it,
// translated to eBPF, and attached as the XDP filter — so anything tcpdump can
// express becomes an in-kernel filter with no packet ever reaching userspace
// unless it matches.
//
// Building this needs libpcap's headers (libpcap-dev / libpcap-devel). The core
// go-afxdp module does not.
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
	"github.com/atoonk/go-afxdp/pcapfilter"
	"github.com/cilium/ebpf"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	expr := flag.String("filter", "tcp port 443 and not src net 192.0.2.0/24",
		"tcpdump filter expression")
	flag.Parse()

	// Compile up front so a typo is reported before anything is attached.
	// pcapfilter.Match would defer the same error to Open, which is handy
	// inline but less clear for a command-line argument.
	m, err := pcapfilter.Compile(*expr)
	if err != nil {
		log.Fatalf("bad -filter: %v", err)
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(m),
		// Keeps ARP, IPv6 ND, SSH and DNS replies with the kernel, so running
		// this on the interface you are logged in through cannot lock you out.
		afxdp.WithKeepManagement())
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("open %s: filter rejected by the kernel verifier:\n%+v", *iface, ve)
		}
		log.Fatalf("open %s: %v", *iface, err)
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

// summary prints one line per captured frame.
func summary(f []byte) string {
	l3 := 14
	if len(f) >= 14 && binary.BigEndian.Uint16(f[12:]) == afxdp.EtherTypeVLAN {
		l3 = 18
	}
	if len(f) < l3+28 {
		return fmt.Sprintf("%d bytes (short)", len(f))
	}
	return fmt.Sprintf("%4d bytes  %s:%d -> %s:%d", len(f),
		net.IP(f[l3+12:l3+16]), binary.BigEndian.Uint16(f[l3+20:]),
		net.IP(f[l3+16:l3+20]), binary.BigEndian.Uint16(f[l3+22:]))
}
