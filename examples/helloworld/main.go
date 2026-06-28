// helloworld is the smallest afxdp program: it captures ICMP echo (ping)
// packets on an interface and prints a one-line summary of each, plus periodic
// stats.
//
//	go build -o helloworld ./examples/helloworld
//	sudo ./helloworld -iface eth0
//
// Then ping the host from another machine and you'll see lines scroll by. It
// filters to just ICMP echo so it's safe to run on a live interface — all other
// traffic (SSH included) keeps flowing to the kernel untouched. Press Ctrl-C to
// stop.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	statsEvery := flag.Duration("stats", 5*time.Second, "how often to print stats")
	flag.Parse()

	// Open binds an AF_XDP socket to every rx queue and attaches the XDP
	// program. The filter says which traffic to redirect to us — here just ICMP
	// echo (ping), so we don't steal anything else from the kernel. A filter is
	// required; without one Open would redirect every packet and could cut off
	// your own connectivity.
	fleet, err := afxdp.Open(*iface, afxdp.WithFilter(afxdp.MatchICMPEcho()))
	if err != nil {
		log.Fatalf("open %s: %v", *iface, err)
	}

	// Info() reports how we're actually running: queues, mode, zero-copy,
	// driver, frame budget — e.g.
	//   started: eth0: 8 queues, zero-copy, native XDP, 4096x2048B frames, driver ena
	if info, err := fleet.Info(); err == nil {
		log.Printf("started: %s", info)
	}

	// One receive goroutine per queue: Fill -> Poll -> Receive -> Recycle.
	for _, xsk := range fleet.Sockets() {
		go func(xsk *afxdp.Socket) {
			for {
				xsk.Fill(xsk.NumFreeFillSlots()) // give the kernel buffers
				n, err := xsk.Poll(-1)           // block until packets arrive
				if err != nil {
					return
				}
				descs := xsk.Receive(n)
				for _, d := range descs {
					fmt.Println(summary(xsk.GetFrame(d)))
				}
				xsk.Recycle(descs) // return frames to be filled again
			}
		}(xsk)
	}

	// Print aggregate stats every few seconds. Stats() sums every queue's
	// counters for us, so the receive loops above don't track anything.
	go func() {
		t := time.NewTicker(*statsEvery)
		defer t.Stop()
		var last uint64
		for range t.C {
			s, err := fleet.Stats()
			if err != nil {
				continue
			}
			log.Printf("[stats] %s  (+%d rx since last)", s, s.RxPackets-last)
			last = s.RxPackets
		}
	}()

	// Wait for Ctrl-C, then exit. Open attached via a BPF link, so the kernel
	// auto-detaches the XDP program when this process exits (Linux >= 5.9).
	// Call fleet.Close() if you want to detach explicitly.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("stopping")
}

// summary renders a one-line description of an Ethernet frame.
func summary(frame []byte) string {
	if len(frame) < 14 {
		return fmt.Sprintf("%d bytes (runt)", len(frame))
	}
	dst := net.HardwareAddr(frame[0:6])
	src := net.HardwareAddr(frame[6:12])
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	return fmt.Sprintf("%d bytes  %s -> %s  ethertype=0x%04x", len(frame), src, dst, etherType)
}
