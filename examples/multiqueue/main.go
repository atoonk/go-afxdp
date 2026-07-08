//go:build linux

// multiqueue captures traffic across every rx queue on an interface at once.
// It opens a Fleet (one AF_XDP socket per queue, all under one XDP program),
// runs one goroutine per queue, and prints the aggregate packet rate each
// second. This is the way to see all RSS-distributed traffic, not just the
// share that lands on queue 0.
//
//	go build -o multiqueue ./examples/multiqueue
//	sudo ./multiqueue -iface eth0
//
// WARNING: it uses MatchAll, so it redirects EVERY packet on the interface to
// userspace — the kernel stops receiving them. Run it on a dedicated test
// interface, not your management/SSH NIC, or you'll cut yourself off.
//
// Press Ctrl-C to stop; the Fleet detaches the program and closes every socket.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/vishvananda/netlink"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	yes := flag.Bool("yes", false, "skip the confirmation prompt")
	flag.Parse()

	n, err := afxdp.CountQueues(*iface)
	if err != nil {
		log.Fatalf("count queues: %v", err)
	}
	log.Printf("%s has %d rx queues; binding all of them", *iface, n)

	// MatchAll redirects EVERY packet on the interface to userspace, so the
	// kernel stops receiving any of it. Confirm before doing that on a NIC that
	// might be carrying your own connection.
	confirmMatchAll(*iface, *yes)

	// A Fleet is a collection of AF_XDP sockets (XSKs) — one per rx/tx queue on
	// the interface — bound together under one XDP program. Think of it as the
	// set of per-queue workers we're about to run: Open binds every queue and
	// hands us one socket for each.
	fleet, err := afxdp.Open(*iface, afxdp.WithFilter(afxdp.MatchAll()))
	if err != nil {
		log.Fatalf("open fleet: %v", err)
	}
	defer fleet.Close()

	// Info() reports how the fleet is actually running (mode, zero-copy, ...).
	if info, err := fleet.Info(); err == nil {
		log.Print(info)
	}

	// Native XDP attach bounces the link on many NICs (~10s on ixgbe); wait
	// for it so the quiet start doesn't read as "receiving nothing".
	log.Printf("waiting for the link to come up...")
	if fleet.WaitLinkUp(15 * time.Second) {
		log.Printf("link up")
	} else {
		log.Printf("warning: link not up after 15s; continuing anyway")
	}

	// The receive goroutines just drain their queue — no counting. The Fleet
	// tracks packet and drop counters for us; we read them with Stats() below.
	stop := make(chan struct{})
	for _, xsk := range fleet.Sockets() {
		go func(xsk *afxdp.Socket) {
			for {
				select {
				case <-stop:
					return
				default:
				}
				xsk.Fill(xsk.NumFreeFillSlots())
				nrx, err := xsk.Poll(200 * time.Millisecond) // short timeout so we notice stop
				if err != nil {
					return
				}
				xsk.Recycle(xsk.Receive(nrx))
			}
		}(xsk)
	}

	// Report the aggregate rate once a second using Fleet.Stats(), which sums
	// every queue's counters — no per-packet bookkeeping in the loop above.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-sig:
			close(stop)
			log.Printf("stopping")
			return
		case <-ticker.C:
			s, err := fleet.Stats()
			if err != nil {
				log.Printf("stats: %v", err)
				continue
			}
			log.Printf("%6d pkt/s  (total %s)", s.RxPackets-last, s)
			last = s.RxPackets
		}
	}
}

// confirmMatchAll warns that redirecting all traffic can cut off the host and
// asks for confirmation, unless skip is set. It proceeds only on an explicit yes.
func confirmMatchAll(iface string, skip bool) {
	if skip {
		return
	}
	fmt.Fprintf(os.Stderr, "\nWARNING: this redirects ALL traffic on %s to userspace — the kernel will stop receiving it.\n", iface)
	if isDefaultRouteIface(iface) {
		fmt.Fprintf(os.Stderr, "  %s is your DEFAULT-ROUTE interface: you will almost certainly lose access (SSH, etc.).\n", iface)
	} else {
		fmt.Fprintln(os.Stderr, "  If this is your primary interface you may lose access (SSH, etc.).")
	}
	fmt.Fprint(os.Stderr, "Continue? [y/N]: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		// proceed
	default:
		log.Fatal("aborted (pass -yes to skip this prompt)")
	}
}

// isDefaultRouteIface reports whether iface is the interface the default route
// egresses — i.e. most likely how you are connected to this machine.
func isDefaultRouteIface(iface string) bool {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return false
	}
	routes, err := netlink.RouteGet(net.IPv4(8, 8, 8, 8))
	if err != nil || len(routes) == 0 {
		return false
	}
	return routes[0].LinkIndex == link.Attrs().Index
}
