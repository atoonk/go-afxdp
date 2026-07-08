//go:build linux

// udpreflector bounces UDP packets back to their sender. It binds the given
// UDP port across one or more rx queues with a single call to afxdp.Open, then
// for every packet swaps the Ethernet, IPv4, and UDP src/dst fields and
// transmits it back out — a wire-speed UDP echo server that never touches the
// kernel network stack.
//
//	go build -o udpreflector ./examples/udpreflector
//	sudo ./udpreflector -iface eth0 -port 7000 -queues 0
//
// Test it from another host:
//
//	echo hello | nc -u -w1 <iface-ip> 7000   # the bytes come straight back
//
// Because the filter is installed in XDP, only UDP/<port> is taken; SSH and
// everything else still reach the kernel normally. -queues 0 (the default)
// binds every rx queue so all RSS-distributed traffic for the port is caught.
//
// Note: swapping src/dst leaves the IPv4 and UDP checksums valid (the checksum
// is a commutative sum), so the reflector doesn't recompute them — it relies on
// the *incoming* packet already having a correct on-wire checksum, which it does
// on a real NIC. On a veth pair this can fail: the sender uses TX checksum
// offload, so the frame the AF_XDP socket sees has an incomplete checksum, and
// the reflected copy is then dropped by the receiver. Disable it with
// `ethtool -K <veth> tx off` to test on veth, or just test on real hardware.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	port := flag.Int("port", 7000, "UDP port to reflect")
	queues := flag.Int("queues", 0, "rx queues to bind (0 = all)")
	flag.Parse()

	// One call: attach an XDP UDP-port filter, bind the queues, register
	// sockets. The XDP mode is auto-selected (native zero-copy where available,
	// falling back to generic on virtual devices like veth).
	//
	// The returned Fleet is a collection of AF_XDP sockets (XSKs) — one per
	// rx/tx queue — i.e. the set of per-queue workers we'll run below, one
	// goroutine each.
	fleet, err := afxdp.Open(*iface,
		afxdp.WithUDPPorts(uint16(*port)),
		afxdp.WithQueues(*queues),
	)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer fleet.Close()
	log.Printf("reflecting UDP/%d on %s", *port, *iface)

	// Native XDP attach bounces the link on many NICs (~10s on ixgbe); wait
	// for it so the quiet start doesn't read as "receiving nothing".
	log.Printf("waiting for the link to come up...")
	if fleet.WaitLinkUp(15 * time.Second) {
		log.Printf("link up")
	} else {
		log.Printf("warning: link not up after 15s; continuing anyway")
	}
	if info, err := fleet.Info(); err == nil {
		log.Print(info) // e.g. eth0: 4 queues, zero-copy, native XDP, 4096x2048B frames
	}

	for q, xsk := range fleet.Sockets() {
		go reflectQueue(q, xsk)
	}

	// Clean up on Ctrl-C / SIGTERM: without this the deferred fleet.Close never
	// runs, leaving the XDP filter attached to the interface. (Open also uses a
	// BPF link that the kernel auto-detaches on exit, so even a kill -9 is
	// cleaned up on Linux >= 5.9 — but detaching explicitly is still correct.)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Report the rate once a second using Fleet.Stats(): TxPackets is what we
	// reflected back, RxPackets what came in. No per-packet counting needed.
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastTx uint64
	for {
		select {
		case <-sig:
			log.Printf("stopping; detaching XDP filter")
			return // runs deferred fleet.Close()
		case <-ticker.C:
			s, err := fleet.Stats()
			if err != nil {
				log.Printf("stats: %v", err)
				continue
			}
			log.Printf("%d pkt/s reflected  (total %s)", s.TxPackets-lastTx, s)
			lastTx = s.TxPackets
		}
	}
}

// reflectQueue runs one queue's receive+transmit loop. A single goroutine owns
// both directions of this socket, so no locking is needed.
func reflectQueue(q int, xsk *afxdp.Socket) {
	for {
		// Reclaim sent frames and keep the kernel supplied with rx buffers.
		xsk.Complete(xsk.NumCompleted())
		xsk.Fill(xsk.NumFreeFillSlots())

		n, err := xsk.Poll(-1)
		if err != nil {
			log.Printf("queue %d poll: %v", q, err)
			return
		}
		rx := xsk.Receive(n)
		if len(rx) == 0 {
			continue
		}

		tx := xsk.Alloc(len(rx))
		built := 0
		for i := range rx {
			if built >= len(tx) {
				break // transmit pool momentarily drained; drop the rest
			}
			in := xsk.GetFrame(rx[i])
			if len(in) < 42 {
				continue
			}
			out := xsk.GetFrame(tx[built])
			copy(out, in)
			reflect(out)
			tx[built].Len = uint32(len(in))
			built++
		}
		xsk.Transmit(tx[:built])
		xsk.Recycle(rx)
	}
}

// reflect swaps the source and destination at every layer of an
// Ethernet/IPv4/UDP frame, turning a packet addressed to us into its reply.
// Swapping src<->dst leaves both the IPv4 header checksum and the UDP checksum
// unchanged (the checksum is a sum, and addition is commutative), so there is
// nothing to recompute.
func reflect(f []byte) {
	swap(f, 0, 6, 6)   // Ethernet dst <-> src MAC
	swap(f, 26, 30, 4) // IPv4 src <-> dst address (14 + 12, 14 + 16)
	swap(f, 34, 36, 2) // UDP src <-> dst port (14 + 20 + 0, +2)
}

// swap exchanges two equal-length, non-overlapping byte ranges in place.
func swap(f []byte, a, b, n int) {
	for i := 0; i < n; i++ {
		f[a+i], f[b+i] = f[b+i], f[a+i]
	}
}
