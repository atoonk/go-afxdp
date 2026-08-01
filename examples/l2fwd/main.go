//go:build linux

// l2fwd is a minimal L2 reflector: it receives frames on one queue, swaps the
// source and destination MAC addresses, and transmits them back out the same
// interface. It exercises both the receive and transmit paths.
//
//	go build -o l2fwd ./examples/l2fwd
//	sudo ./l2fwd -iface eth0 -queue 0
//
// NOTE: this is a teaching example, not a production pattern. Pure L2 work —
// reflecting, forwarding, dropping — belongs in the XDP program itself, where
// it stays in the driver and never crosses into userspace: return XDP_TX to
// bounce a frame, bpf_redirect() to forward it, XDP_DROP to drop it. Reach for
// AF_XDP (and this library) when you need the packet in userspace — to modify
// it with logic that doesn't fit in eBPF, run a userspace TCP/TLS/WireGuard
// stack, do stateful DPI, generate traffic, and so on. l2fwd just happens to be
// the smallest program that shows the receive and transmit APIs together.
//
// Because the receive and transmit frame pools are disjoint (that is what makes
// a Socket safe to drive from two goroutines), forwarding copies each frame
// from a receive buffer into a transmit buffer. This example stays single-
// goroutine for clarity; see the package doc for the concurrent pattern.
package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/vishvananda/netlink"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	queue := flag.Int("queue", 0, "rx queue id to bind")
	flag.Parse()

	link, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("interface %s: %v", *iface, err)
	}
	ifindex := link.Attrs().Index

	prog, err := afxdp.NewProgram(*queue + 1)
	if err != nil {
		log.Fatalf("new program: %v", err)
	}
	if err := prog.Attach(ifindex, 0); err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer prog.Detach(ifindex)

	xsk, err := afxdp.NewSocket(ifindex, *queue, nil)
	if err != nil {
		log.Fatalf("new socket: %v", err)
	}
	defer xsk.Close()
	if err := prog.Register(*queue, xsk.FD()); err != nil {
		log.Fatalf("register: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; prog.Detach(ifindex); os.Exit(0) }()

	// Startup info. At the low level there's no Fleet.Info(), but the Socket
	// exposes the same building blocks (here, whether zero-copy was granted).
	zc, _ := xsk.ZeroCopy()
	log.Printf("reflecting on %s queue %d (zero-copy=%v)", *iface, *queue, zc)

	// Periodic stats. Socket.Stats() is a lock-free snapshot, so a monitoring
	// goroutine can read it while the main loop runs.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			if s, err := xsk.Stats(); err == nil {
				log.Printf("[stats] %s", s)
			}
		}
	}()

	var el errLog
	for {
		// Reclaim any transmit frames the kernel finished sending.
		xsk.Complete(xsk.NumCompleted())

		// Keep the kernel supplied with receive buffers and wait for packets.
		xsk.Fill(xsk.NumFreeFillSlots())
		n, err := xsk.Poll(-1)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Print("socket closed; exiting")
				return
			}
			// Never crash (or log unbounded) on an error in the packet loop:
			// a dataplane rides through it and says so at most once a second.
			el.printf("poll: %v", err)
			continue
		}
		rx := xsk.Receive(n)
		if len(rx) == 0 {
			continue
		}

		// Reserve one transmit frame per received frame.
		tx := xsk.Alloc(len(rx))
		for i := range tx {
			in := xsk.GetFrame(rx[i])
			out := xsk.GetFrame(tx[i])
			copy(out, in)
			swapMAC(out)
			tx[i].Len = uint32(len(in))
		}
		xsk.Transmit(tx)

		// Done reading the received frames; return them to the rx pool.
		xsk.Recycle(rx)
	}
}

// swapMAC exchanges the destination and source MAC addresses in place.
func swapMAC(frame []byte) {
	if len(frame) < 12 {
		return
	}
	var tmp [6]byte
	copy(tmp[:], frame[0:6])
	copy(frame[0:6], frame[6:12])
	copy(frame[6:12], tmp[:])
}

// errLog logs at most one line per second, counting suppressed repeats. A
// dataplane loop can see millions of errors per second; neither crashing the
// process nor logging unbounded is acceptable there. One instance per
// goroutine, so no locking is needed.
type errLog struct {
	last       time.Time
	suppressed int
}

func (e *errLog) printf(format string, args ...any) {
	if time.Since(e.last) < time.Second {
		e.suppressed++
		return
	}
	if e.suppressed > 0 {
		format += " (+%d suppressed)"
		args = append(args, e.suppressed)
	}
	log.Printf(format, args...)
	e.last = time.Now()
	e.suppressed = 0
}
