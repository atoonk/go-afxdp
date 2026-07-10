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
	"context"
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
	"golang.org/x/time/rate"
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
	rate := flag.Int("rate", 0, "target transmit rate in packets/sec, spread across all queues (0 = as fast as possible)")
	chunkFlag := flag.Int("chunk", 0, "packets reserved per pacing wait, per queue (0 = auto ~500µs); smaller = smoother/less bursty, larger = burstier")
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
	rateNote := ""
	if *rate > 0 {
		rateNote = ", paced to " + strconv.Itoa(*rate) + " pps"
	}
	log.Printf("blasting %s:%d  (%s %s -> %s %s, %d-byte frames%s%s)",
		*dstIP, *dstPort, srcIP, srcMAC, dstMAC, dip, *size, vlanNote, rateNote)

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
	// ctx unblocks the rate limiter's WaitN the instant we shut down, so a paced
	// blast stops promptly instead of finishing its current wait.
	ctx, cancel := context.WithCancel(context.Background())
	socks := fleet.Sockets()
	// -rate is a total across all queues, split into per-queue shares. Guard the
	// degenerate case: a rate below the queue count would hand some queues a
	// share of 0, which blast() reads as "unpaced" — so a tiny -rate would blast
	// at full line rate, the exact opposite of what was asked. Refuse it.
	if *rate > 0 && *rate < len(socks) {
		log.Fatalf("-rate %d is below the queue count %d; each queue needs at least 1 pps — raise -rate or lower -queues", *rate, len(socks))
	}
	rates := splitRate(*rate, len(socks))
	for i, xsk := range socks {
		pps := 0
		if rates != nil {
			pps = rates[i]
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			blast(ctx, xsk, template, srcPortOff, uint16(1024+i*64), pps, *chunkFlag, &bytes, &stop)
		}()
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
	cancel()  // wake any goroutine blocked in the rate limiter's WaitN
	wg.Wait() // let TX drain and the goroutines exit before detaching
	log.Println("stopping")
	fleet.Close()
}

// batch is how many frames blast hands the kernel per send: big enough to
// amortize the send syscall, small enough to keep the pacer's quantum low.
const batch = 256

// pacerBurst sizes the rate limiter's token bucket, expressed as a duration of
// credit. The bucket cap is what gives a load generator the semantics it wants:
// when the NIC stalls for a moment, tokens accumulate only up to the cap and
// the rest are forfeited — so recovery is a bounded catch-up, never a full
// second of backlog dumped at once (which would overshoot the target). It must
// also comfortably exceed one time.Sleep oversleep (Go's sub-millisecond sleeps
// overshoot ~1ms under load); measured on the 100G pair, a ~1ms-equivalent cap
// sagged to 84M pps against a 100M request while 10ms holds 100.0M.
const pacerBurst = 10 * time.Millisecond

// newLimiter builds a token-bucket rate limiter for pps packets/sec. The bucket
// holds pacerBurst worth of tokens, floored at a few batches so even a low rate
// can still admit whole batches.
func newLimiter(pps int) *rate.Limiter {
	burst := int(float64(pps) * pacerBurst.Seconds())
	if burst < 4*batch {
		burst = 4 * batch
	}
	return rate.NewLimiter(rate.Limit(pps), burst)
}

// chunkInterval is the wall-clock span a pacing reservation should cover. It
// trades the two failure modes of chunked pacing against each other: too short
// and time.Sleep's wakeup jitter becomes a large fraction of the interval, so
// the achieved rate sags below target; too long and each reservation is drained
// as one big line-rate microburst, which overruns shallow buffers and cloud
// traffic shapers (measured on an AWS same-subnet path: a 4096-packet burst at
// 4M pps lost ~13% to silent SDN shaping, a 256-packet burst ~7%, and unpaced
// hardware-smoothed traffic 0%). ~500µs is long enough that jitter is
// negligible and short enough to keep the burst small. It cannot make paced
// traffic as smooth as unpaced — only the NIC pacing itself is truly gap-free —
// but it minimizes the burst for a given accuracy.
const chunkInterval = 500 * time.Microsecond

// pacingChunk picks how many packets to reserve per WaitN for a per-queue rate
// of pps. It is chunkInterval worth of packets, rounded to whole batches (so the
// send loop consumes exactly what was reserved), floored at one batch and capped
// at the token bucket (WaitN of more than the burst can never be satisfied). A
// positive override replaces the computed value (still clamped).
func pacingChunk(pps, override, burst int) int {
	chunk := int(float64(pps) * chunkInterval.Seconds())
	if override > 0 {
		chunk = override
	}
	chunk = (chunk / batch) * batch
	if chunk < batch {
		chunk = batch
	}
	if chunk > burst {
		chunk = (burst / batch) * batch
	}
	return chunk
}

// blast is one queue's transmit loop. It keeps the tx ring full: reap
// completions, allocate as many frames as there is ring space, stamp each with
// an incrementing source port, and transmit. One goroutine owns this socket's
// transmit side, so no locking is needed.
//
// A non-zero pps paces this queue to that rate with a golang.org/x/time/rate
// limiter; pps <= 0 transmits as fast as the NIC will go. Each WaitN reserves a
// chunk of packets (see pacingChunk), then the chunk is transmitted in
// batch-sized SendFunc calls. Reserving a chunk rather than a single batch
// amortizes time.Sleep's wakeup jitter over the whole chunk (reserving one
// batch at a time let that jitter sag the achieved rate ~1%); pacingChunk keeps
// the chunk only as large as that needs, because a larger chunk is a larger
// line-rate microburst that policed paths drop. WaitN returns an error only
// when ctx is cancelled (shutdown). The bucket (sized by pacerBurst) bounds
// catch-up after a stall — surplus beyond it is forfeited, not repaid.
//
// NOTE: paced output is inherently bursty at the chunk granularity — the NIC
// emits a chunk at line rate, then idles until the next reservation matures. The
// average matches the target, but instantaneous rate does not, so a rate-policed
// path (e.g. AWS) may drop packets that an unpaced (NIC-smoothed) run does not.
func blast(ctx context.Context, xsk *afxdp.Socket, template []byte, srcPortOff int, startPort uint16, pps, chunkOverride int, bytes *atomic.Uint64, stop *atomic.Bool) {
	port := startPort
	// SendFunc fills each frame in place and handles all the ring bookkeeping
	// (reaping completions, kicking, never stalling on a full ring). We just
	// stamp an incrementing source port to spread the receiver's RSS.
	fill := func(i int, frame []byte) int {
		copy(frame, template)
		binary.BigEndian.PutUint16(frame[srcPortOff:], port) // vary UDP source port
		port++
		return len(template)
	}

	if pps <= 0 { // unpaced: keep the ring as full as the NIC allows
		for !stop.Load() {
			n := xsk.SendFunc(batch, fill)
			bytes.Add(uint64(n) * uint64(len(template)))
		}
		return
	}

	lim := newLimiter(pps)
	chunk := pacingChunk(pps, chunkOverride, lim.Burst())
	for !stop.Load() {
		if err := lim.WaitN(ctx, chunk); err != nil {
			return // ctx cancelled: shutting down
		}
		for sent := 0; sent < chunk && !stop.Load(); sent += batch {
			n := xsk.SendFunc(batch, fill)
			bytes.Add(uint64(n) * uint64(len(template)))
		}
	}
}

// splitRate divides a total pps target across n queues, giving queue 0 the
// remainder so the shares sum exactly to total. It returns nil for total <= 0,
// which callers treat as "unpaced". Callers must ensure total >= n so no share
// is zero (a zero share reads as unpaced).
func splitRate(total, n int) []int {
	if total <= 0 {
		return nil
	}
	shares := make([]int, n)
	base := total / n
	for i := range shares {
		shares[i] = base
	}
	shares[0] += total % n
	return shares
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
