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
// It prints receive pps and bit/s once a second, plus drop counters split into
// nic-side (the NIC ran out of rx descriptors) and app-side (this program didn't
// drain its rx ring fast enough, broken out per queue) so you can see whether
// you're losing packets and which stage is the bottleneck.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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
	// WithReceiveHeavy because this is a pure sink: it never transmits, so give
	// the whole UMEM to the receive pool instead of reserving half for tx.
	fleet, err := afxdp.Open(*iface,
		afxdp.WithUDPPorts(uint16(*port)),
		afxdp.WithQueues(*queues),
		afxdp.WithReceiveHeavy(),
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

	go report(fleet, &bytes, *iface)

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

// ethWireOverhead is the on-the-wire Ethernet framing not included in an
// AF_XDP frame length (d.Len): 7-byte preamble + 1-byte start-frame delimiter
// + 4-byte FCS + 12-byte interframe gap. Adding it per packet turns counted
// frame bytes into wire bytes, so Gbit/s reflects link utilization — the
// difference is large for small frames (a 64-byte frame is 88 bytes on the wire),
// which is why raw frame bytes badly understate line-rate use at high pps.
const ethWireOverhead = 24

// report prints, once a second, the receive rate and two kinds of drops so you
// can see whether packets are being lost and where:
//
//   - nic:  packets that arrived on the wire but the NIC had no free rx
//     descriptor to put them in (netdev rx_missed_errors). Non-zero means the
//     receive pipeline as a whole is falling behind the wire.
//   - app:  packets the NIC handed us but WE dropped because our rx ring was
//     full — this program didn't drain fast enough. The per-queue breakdown
//     ([ring-full/q: ...]) shows exactly which rx queue/core is the bottleneck.
//
// Both are drops at or after this NIC. Packets lost in the network/switch before
// they reach here are invisible to any receiver — to see those, compare the
// sender's tx rate to this rx rate.
func report(fleet *afxdp.Fleet, bytes *atomic.Uint64, iface string) {
	socks := fleet.Sockets()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastP, lastB, lastRingFull uint64
	// rx_missed comes from the netdev stats, which ixgbe (and similar drivers)
	// refresh only every ~2s — so a 1-second delta sawtooths between 0 and two
	// seconds' worth. Keep two ticks of history and report the delta over that
	// 2s window (halved) so the nic drop rate reads steady instead of 0/N/0/N.
	missedHist := [2]uint64{readMissed(iface), readMissed(iface)}
	perQLast := make([]uint64, len(socks))
	for range t.C {
		// One pass over the sockets: total rx, total rx-ring-full drops, and the
		// per-queue rx-ring-full so we can point at the hot queue.
		var rxPkts, ringFull uint64
		perQ := make([]uint64, len(socks))
		for i, xsk := range socks {
			st, err := xsk.Stats()
			if err != nil {
				continue
			}
			rxPkts += st.Received
			ringFull += st.KernelStats.Rx_ring_full
			perQ[i] = st.KernelStats.Rx_ring_full
		}

		b := bytes.Load()
		pps := rxPkts - lastP
		gbits := float64((b-lastB)+pps*ethWireOverhead) * 8 / 1e9 // wire rate

		var hot strings.Builder
		for i := range socks {
			if d := perQ[i] - perQLast[i]; d > 0 {
				fmt.Fprintf(&hot, " q%d=%d", i, d)
			}
			perQLast[i] = perQ[i]
		}
		perQueue := ""
		if hot.Len() > 0 {
			perQueue = "   [ring-full/q:" + hot.String() + " ]"
		}

		missed := readMissed(iface)
		nicDrops := (missed - missedHist[0]) / 2 // delta over the last ~2s, per second
		missedHist[0], missedHist[1] = missedHist[1], missed

		log.Printf("%d rx pps  %.2f Gbit/s   drops: nic=%d/s app=%d/s%s",
			pps, gbits, nicDrops, ringFull-lastRingFull, perQueue)

		lastP, lastB, lastRingFull = rxPkts, b, ringFull
	}
}

// readMissed returns the interface's cumulative rx_missed_errors — packets the
// NIC received off the wire but had no rx descriptor for. Returns 0 if the
// counter can't be read (e.g. a device without it).
func readMissed(iface string) uint64 {
	data, err := os.ReadFile("/sys/class/net/" + iface + "/statistics/rx_missed_errors")
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v
}
