//go:build linux

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
	"strconv"
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
	vlan := flag.Int("vlan", 0, "802.1Q VLAN ID to tag frames with (0 = untagged)")
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
	vlanNote := ""
	if *vlan > 0 {
		vlanNote = " " + "vlan " + strconv.Itoa(*vlan)
	}
	log.Printf("blasting %s:%d  (%s %s -> %s %s, %d-byte frames%s)",
		*dstIP, *dstPort, srcIP, srcMAC, dstMAC, dip, *size, vlanNote)

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
	log.Printf("waiting for the link to come up (native XDP attach bounces it, ~10s on some NICs)...")
	if fleet.WaitLinkUp(15 * time.Second) {
		log.Printf("link up; blasting for %s", *duration)
	} else {
		log.Printf("warning: %s not up after 15s; transmitting anyway", *iface)
	}

	template, srcPortOff := buildFrame(srcMAC, dstMAC, srcIP, dip, uint16(*dstPort), *size, *vlan)

	// stop tells every goroutine to wind down; wg lets us wait for them so the
	// link (and the host's connectivity) is released cleanly before we detach.
	var stop atomic.Bool
	var bytes atomic.Uint64
	var wg sync.WaitGroup
	for i, xsk := range fleet.Sockets() {
		wg.Add(1)
		go func(i int, xsk *afxdp.Socket) {
			defer wg.Done()
			blast(xsk, template, srcPortOff, uint16(1024+i*64), &bytes, &stop)
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
func blast(xsk *afxdp.Socket, template []byte, srcPortOff int, startPort uint16, bytes *atomic.Uint64, stop *atomic.Bool) {
	const batch = 256
	port := startPort
	for !stop.Load() {
		// SendFunc fills each frame in place and handles all the ring
		// bookkeeping (reaping completions, kicking, never stalling on a full
		// ring). We just stamp an incrementing source port to spread the
		// receiver's RSS.
		n := xsk.SendFunc(batch, func(i int, frame []byte) int {
			copy(frame, template)
			binary.BigEndian.PutUint16(frame[srcPortOff:], port) // vary UDP source port
			port++
			return len(template)
		})
		bytes.Add(uint64(n) * uint64(len(template)))
	}
}

// ethWireOverhead is the on-the-wire Ethernet framing not included in a frame
// length: 7-byte preamble + 1-byte start-frame delimiter + 4-byte FCS + 12-byte
// interframe gap. Adding it per packet turns counted frame bytes into wire
// bytes, so Gbit/s reflects link utilization — the difference is large for small
// frames (a 64-byte frame is 88 bytes on the wire), which is why raw frame bytes
// badly understate line-rate use at high pps.
const ethWireOverhead = 24

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
		gbits := float64((b-lastB)+pps*ethWireOverhead) * 8 / 1e9 // wire rate
		log.Printf("%d pps  %.2f Gbit/s", pps, gbits)
		lastP, lastB = s.TxPackets, b
	}
}

// buildFrame builds the Ethernet+IPv4+UDP template and returns it along with
// the byte offset of the UDP source port (which the TX loop stamps per packet).
// A non-zero vlan inserts an 802.1Q tag after the source MAC, shifting every
// header past it by 4 bytes — hence returning the source-port offset instead of
// hardcoding it. The UDP checksum is left 0 (legal for IPv4), so varying the
// source port per packet needs no recompute; the IPv4 header checksum doesn't
// cover the ports, so it stays valid too.
func buildFrame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dstPort uint16, size, vlan int) ([]byte, int) {
	ethLen := 14 // dst + src MAC + ethertype
	if vlan > 0 {
		ethLen += 4 // 802.1Q tag
	}
	if minSize := ethLen + 28; size < minSize { // 20 IPv4 + 8 UDP
		size = minSize
	}
	f := make([]byte, size)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)

	et := 12 // offset of the (inner) ethertype
	if vlan > 0 {
		binary.BigEndian.PutUint16(f[12:], 0x8100)              // 802.1Q TPID
		binary.BigEndian.PutUint16(f[14:], uint16(vlan)&0x0fff) // PCP 0, DEI 0, VID
		et = 16
	}
	binary.BigEndian.PutUint16(f[et:], 0x0800) // IPv4

	ip := et + 2                                          // IPv4 header start
	f[ip] = 0x45                                          // IPv4, IHL 5
	f[ip+8] = 64                                          // TTL
	f[ip+9] = 17                                          // UDP
	binary.BigEndian.PutUint16(f[ip+2:], uint16(size-ip)) // IP total length
	copy(f[ip+12:ip+16], srcIP.To4())
	copy(f[ip+16:ip+20], dstIP.To4())
	binary.BigEndian.PutUint16(f[ip+10:], ipChecksum(f[ip:ip+20]))

	udp := ip + 20                                          // UDP header start
	binary.BigEndian.PutUint16(f[udp:], 1024)               // UDP src port (varied at TX)
	binary.BigEndian.PutUint16(f[udp+2:], dstPort)          // UDP dst port
	binary.BigEndian.PutUint16(f[udp+4:], uint16(size-udp)) // UDP length
	// UDP checksum (f[udp+6:udp+8]) left zero.
	return f, udp
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
