// blast is a UDP packet generator built on AF_XDP: it builds a UDP frame
// directly in the UMEM and transmits it as fast as the NIC will go, across
// every tx queue. It's the sender counterpart to the drop example — point one
// at the other to measure end-to-end userspace TX→RX throughput.
//
//	go build -o blast ./examples/blast
//	sudo ./blast -iface eth0 -dst-ip 10.0.0.2 -dst-port 9999 -size 64
//
// It transmits to dst-ip:dst-port. The source MAC/IP are taken from -iface; the
// destination MAC is resolved from the kernel's ARP table (ping the target
// first so it's populated, or pass -dst-mac). The UDP source port is varied per
// packet so the receiver spreads the flood across its rx queues (RSS).
//
// It attaches a no-op XDP program (afxdp.MatchNone) purely to enable the
// driver's zero-copy datapath for transmit; no receive traffic is touched.
//
// WARNING: this saturates the link. Do NOT run it on your management/SSH
// interface — line-rate TX starves the host's own traffic and you'll lose the
// session. It stops after -duration (default 10s) so a mistake self-recovers.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/vishvananda/netlink"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to transmit from")
	dstIP := flag.String("dst-ip", "", "destination IP (required)")
	dstPort := flag.Int("dst-port", 9999, "destination UDP port")
	dstMACs := flag.String("dst-mac", "", "destination MAC (default: resolve via ARP)")
	srcIPs := flag.String("src-ip", "", "source IP (default: the interface's first IPv4)")
	size := flag.Int("size", 64, "total frame size in bytes (>=42)")
	queues := flag.Int("queues", 0, "tx queues to use (0 = all)")
	duration := flag.Duration("duration", 10*time.Second, "how long to blast (0 = until Ctrl-C)")
	flag.Parse()

	if *dstIP == "" {
		log.Fatal("need -dst-ip")
	}
	dip := net.ParseIP(*dstIP).To4()
	if dip == nil {
		log.Fatalf("bad -dst-ip %q", *dstIP)
	}

	link, err := netlink.LinkByName(*iface)
	if err != nil {
		log.Fatalf("interface %s: %v", *iface, err)
	}
	srcMAC := link.Attrs().HardwareAddr
	srcIP := pickSrcIP(link, *srcIPs)
	dstMAC := pickDstMAC(link, dip, *dstMACs)
	log.Printf("blasting %s:%d  (%s %s -> %s %s, %d-byte frames)",
		*dstIP, *dstPort, srcIP, srcMAC, dstMAC, dip, *size)

	// Attach a no-op program (MatchNone) so we get the zero-copy TX datapath
	// without stealing any receive traffic, and bind one socket per queue.
	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(afxdp.MatchNone()),
		afxdp.WithQueues(*queues),
	)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	if info, err := fleet.Info(); err == nil {
		log.Print(info)
	}

	// Native XDP attach resets the NIC; on ixgbe and similar the 10G link then
	// renegotiates for several seconds, during which nothing can transmit. Wait
	// for it to come back up so -duration is time spent actually blasting.
	if waitLinkUp(*iface, 15*time.Second) {
		log.Printf("link up; blasting for %s", *duration)
	} else {
		log.Printf("warning: %s not up after 15s; transmitting anyway", *iface)
	}

	template := buildFrame(srcMAC, dstMAC, srcIP, dip, uint16(*dstPort), *size)

	// stop tells every goroutine to wind down; wg lets us wait for them so the
	// link (and the host's connectivity) is released cleanly before we detach.
	var stop atomic.Bool
	var bytes atomic.Uint64
	var wg sync.WaitGroup
	for i, xsk := range fleet.Sockets() {
		wg.Add(1)
		go func(i int, xsk *afxdp.Socket) {
			defer wg.Done()
			blast(xsk, template, uint16(1024+i*64), &bytes, &stop)
		}(i, xsk)
	}
	wg.Add(1)
	go func() { defer wg.Done(); report(fleet, &bytes, &stop) }()

	// Stop on Ctrl-C, or after -duration so a run on the wrong NIC self-recovers.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	if *duration > 0 {
		select {
		case <-sig:
		case <-time.After(*duration):
		}
	} else {
		<-sig
	}
	stop.Store(true)
	wg.Wait() // let TX drain and the goroutines exit before detaching
	log.Println("stopping")
	fleet.Close()
}

// blast is one queue's transmit loop. It keeps the tx ring full: reap
// completions, allocate as many frames as there is ring space, stamp each with
// an incrementing source port, and transmit. One goroutine owns this socket's
// transmit side, so no locking is needed.
func blast(xsk *afxdp.Socket, template []byte, startPort uint16, bytes *atomic.Uint64, stop *atomic.Bool) {
	const batch = 256
	port := startPort
	for !stop.Load() {
		// SendFunc fills each frame in place and handles all the ring
		// bookkeeping (reaping completions, kicking, never stalling on a full
		// ring). We just stamp an incrementing source port to spread the
		// receiver's RSS.
		n := xsk.SendFunc(batch, func(i int, frame []byte) int {
			copy(frame, template)
			binary.BigEndian.PutUint16(frame[34:], port) // vary UDP source port
			port++
			return len(template)
		})
		bytes.Add(uint64(n) * uint64(len(template)))
	}
}

// report prints the transmit rate once a second until stopped.
func report(fleet *afxdp.Fleet, bytes *atomic.Uint64, stop *atomic.Bool) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastP, lastB uint64
	for range t.C {
		if stop.Load() {
			return
		}
		s, err := fleet.Stats()
		if err != nil {
			continue
		}
		b := bytes.Load()
		pps := s.TxPackets - lastP
		gbits := float64(b-lastB) * 8 / 1e9
		log.Printf("%d pps  %.2f Gbit/s", pps, gbits)
		lastP, lastB = s.TxPackets, b
	}
}

// buildFrame builds the Ethernet+IPv4+UDP template. The UDP checksum is left 0
// (legal for IPv4), so varying the source port per packet needs no recompute;
// the IPv4 header checksum doesn't cover the ports, so it stays valid too.
func buildFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort uint16, size int) []byte {
	if size < 42 {
		size = 42
	}
	f := make([]byte, size)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:], 0x0800) // IPv4

	f[14] = 0x45                                        // IPv4, IHL 5
	f[22] = 64                                          // TTL
	f[23] = 17                                          // UDP
	binary.BigEndian.PutUint16(f[16:], uint16(size-14)) // IP total length
	copy(f[26:30], srcIP.To4())
	copy(f[30:34], dstIP.To4())
	binary.BigEndian.PutUint16(f[24:], ipChecksum(f[14:34]))

	binary.BigEndian.PutUint16(f[34:], 1024)            // UDP src port (varied at TX)
	binary.BigEndian.PutUint16(f[36:], dstPort)         // UDP dst port
	binary.BigEndian.PutUint16(f[38:], uint16(size-34)) // UDP length
	// UDP checksum (f[40:42]) left zero.
	return f
}

// waitLinkUp polls until the interface is operationally up, or the timeout
// elapses. It returns whether the link came up.
func waitLinkUp(iface string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if l, err := netlink.LinkByName(iface); err == nil && l.Attrs().OperState == netlink.OperUp {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func pickSrcIP(link netlink.Link, override string) net.IP {
	if override != "" {
		if ip := net.ParseIP(override).To4(); ip != nil {
			return ip
		}
		log.Fatalf("bad -src-ip %q", override)
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil || len(addrs) == 0 {
		log.Fatalf("no IPv4 address on %s; pass -src-ip", link.Attrs().Name)
	}
	return addrs[0].IP.To4()
}

func pickDstMAC(link netlink.Link, dstIP net.IP, override string) net.HardwareAddr {
	if override != "" {
		mac, err := net.ParseMAC(override)
		if err != nil {
			log.Fatalf("bad -dst-mac %q: %v", override, err)
		}
		return mac
	}
	neighs, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err == nil {
		for _, n := range neighs {
			if n.IP.Equal(dstIP) && len(n.HardwareAddr) == 6 {
				return n.HardwareAddr
			}
		}
	}
	log.Fatalf("no ARP entry for %s on %s — ping it first, or pass -dst-mac",
		dstIP, link.Attrs().Name)
	return nil
}
