// drop is a UDP packet sink: it receives every packet sent to a UDP port and
// throws it away. Because it does almost no work per packet, it's a handy way
// to measure how fast this library (and your NIC) can pull packets into
// userspace — i.e. raw receive packets-per-second.
//
//	go build -o drop ./examples/drop
//	sudo ./drop -iface eth0 -port 9999
//
// Then blast it from another machine, e.g. with a UDP flood generator:
//
//	# small packets stress pps; large packets stress bandwidth
//	sudo pktgen / udpblast / iperf3 -u -c <host> -p 9999 -b 0 -l 64
//
// It prints receive pps and bit/s once a second, plus the kernel's drop
// counters so you can see when you've saturated the rings.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	port := flag.Int("port", 9999, "UDP port to sink")
	queues := flag.Int("queues", 0, "rx queues to bind (0 = all)")
	flag.Parse()

	// Filter to the one UDP port so only the flood reaches userspace; the rest
	// of the host's traffic stays with the kernel. Mode is auto-selected.
	fleet, err := afxdp.Open(*iface,
		afxdp.WithUDPPorts(uint16(*port)),
		afxdp.WithQueues(*queues),
	)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	if info, err := fleet.Info(); err == nil {
		log.Printf("dropping UDP/%d: %s", *port, info)
	}

	// Summing frame lengths is the only per-packet work we do (for the bit/s
	// figure); packet counts come from Fleet.Stats with no bookkeeping at all.
	var bytes atomic.Uint64
	for _, xsk := range fleet.Sockets() {
		go drop(xsk, &bytes)
	}

	go report(fleet, &bytes)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("stopping")
}

// drop is one queue's receive-and-discard loop: hand the kernel buffers, wait
// for packets, recycle them straight back. No processing — that's the point.
func drop(xsk *afxdp.Socket, bytes *atomic.Uint64) {
	for {
		xsk.Fill(xsk.NumFreeFillSlots())
		n, err := xsk.Poll(-1)
		if err != nil {
			return
		}
		descs := xsk.Receive(n)
		var b uint64
		for _, d := range descs {
			b += uint64(d.Len)
		}
		bytes.Add(b)
		xsk.Recycle(descs)
	}
}

// report prints the receive rate once a second.
func report(fleet *afxdp.Fleet, bytes *atomic.Uint64) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastP, lastB uint64
	for range t.C {
		s, err := fleet.Stats()
		if err != nil {
			continue
		}
		b := bytes.Load()
		pps := s.RxPackets - lastP
		gbits := float64(b-lastB) * 8 / 1e9
		log.Printf("%d pps  %.2f Gbit/s  (rx_ring_full=%d fill_empty=%d)",
			pps, gbits, s.RxRingFull, s.RxFillRingEmpty)
		lastP, lastB = s.RxPackets, b
	}
}
