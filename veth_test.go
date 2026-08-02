//go:build linux

package afxdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// TestKickNeeded checks the transmit kick gating without any hardware: kicks
// are mandatory when the socket was not bound with XDP_USE_NEED_WAKEUP, and
// otherwise follow the tx ring's need-wakeup flag. The zero-copy suppression
// case cannot be observed on veth (copy mode keeps the flag set), so this unit
// test is what covers it.
func TestKickNeeded(t *testing.T) {
	plain := &Socket{options: Options{BindFlags: 0}}
	if !plain.kickNeeded() {
		t.Error("without XDP_USE_NEED_WAKEUP every transmit must kick")
	}

	var flags uint32
	nw := &Socket{options: Options{BindFlags: unix.XDP_USE_NEED_WAKEUP}}
	nw.txRing.Flags = &flags
	if nw.kickNeeded() {
		t.Error("need-wakeup bind with driver awake (flag clear) must suppress the kick")
	}
	flags = unix.XDP_RING_NEED_WAKEUP
	if !nw.kickNeeded() {
		t.Error("need-wakeup bind with driver parked (flag set) must kick")
	}
}

// newVethPair creates an up veth pair with unique names and removes it when
// the test ends. It skips the test where that is not possible (unprivileged,
// no netlink).
func newVethPair(t *testing.T) (string, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root to create veth devices")
	}
	suffix := fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	a, b := "axa"+suffix, "axb"+suffix
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a}, PeerName: b}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Skipf("cannot create veth pair (need CAP_NET_ADMIN): %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })
	for _, name := range []string{a, b} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", name, err)
		}
	}
	return a, b
}

// testFrame is a minimal valid ethernet frame: broadcast destination, local
// experimental ethertype, padded to the 60-byte minimum.
func testFrame() []byte {
	f := make([]byte, 60)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	f[12], f[13] = 0x88, 0xb5
	copy(f[14:], "go-afxdp test")
	return f
}

// openVethFleets opens a transmit-only fleet on ifA and a take-everything
// receive fleet on ifB, both in generic mode, skipping the test where BPF is
// unavailable.
func openVethFleets(t *testing.T, ifA, ifB string, txOpts ...Option) (tx, rx *Fleet) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock (need privileges): %v", err)
	}
	txOpts = append([]Option{WithGenericMode(), WithFilter(MatchNone())}, txOpts...)
	tx, err := Open(ifA, txOpts...)
	if err != nil {
		t.Fatalf("open tx fleet on %s: %v", ifA, err)
	}
	t.Cleanup(func() { tx.Close() })
	rx, err = Open(ifB, WithGenericMode(), WithFilter(MatchAll()))
	if err != nil {
		t.Fatalf("open rx fleet on %s: %v", ifB, err)
	}
	t.Cleanup(func() { rx.Close() })
	if !tx.WaitLinkUp(5 * time.Second) {
		t.Fatal("veth link did not come up")
	}
	return tx, rx
}

// receiveCount drains xsk until want test frames arrived or the deadline
// passes. Only frames carrying the testFrame ethertype are counted — a live
// link also delivers kernel-generated traffic (IPv6 neighbor discovery, MLD)
// that MatchAll redirects along with ours.
func receiveCount(xsk *Socket, want int, deadline time.Time) int {
	got := 0
	for got < want && time.Now().Before(deadline) {
		xsk.Fill(xsk.FreeRxFrames())
		n, err := xsk.Poll(100 * time.Millisecond)
		if err != nil {
			return got
		}
		if n == 0 {
			continue
		}
		descs := xsk.Receive(n)
		for _, d := range descs {
			if f := xsk.GetFrame(d); len(f) >= 14 && f[12] == 0x88 && f[13] == 0xb5 {
				got++
			}
		}
		xsk.Recycle(descs)
	}
	return got
}

// setMTU raises the MTU on both ends of a veth pair so jumbo-sized frames can
// cross it.
func setMTU(t *testing.T, mtu int, names ...string) {
	t.Helper()
	for _, name := range names {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			t.Skipf("cannot set MTU %d on %s: %v", mtu, name, err)
		}
	}
}

// jumboFrame builds a packet of n bytes with the test EtherType and a
// position-dependent payload, so a truncated or mis-ordered reassembly is
// detectable rather than merely shorter.
func jumboFrame(n int) []byte {
	f := make([]byte, n)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	f[12], f[13] = 0x88, 0xb5
	for i := 14; i < n; i++ {
		f[i] = byte(i * 7)
	}
	return f
}

// TestVethMultiBuffer is the jumbo path end to end: a payload several times the
// UMEM frame size must cross the wire as a chain of descriptors and come back
// out byte-identical.
func TestVethMultiBuffer(t *testing.T) {
	ifA, ifB := newVethPair(t)
	setMTU(t, 9000, ifA, ifB)

	// 2048-byte frames against a 6000-byte packet forces a 3-fragment chain.
	const frameSize, pktLen = 2048, 6000
	mb := []Option{WithMultiBuffer(), WithFrameSize(frameSize)}
	tx, rx := openVethFleets(t, ifA, ifB, mb...)
	rx.Close() // reopen the receiver with multi-buffer too
	rxFleet, err := Open(ifB, append([]Option{WithGenericMode(), WithFilter(MatchAll())}, mb...)...)
	if err != nil {
		t.Skipf("cannot open multi-buffer rx fleet on %s: %v", ifB, err)
	}
	defer rxFleet.Close()

	txSock, rxSock := tx.Sockets()[0], rxFleet.Sockets()[0]
	want := jumboFrame(pktLen)

	got := make(chan Packet, 1)
	go func() {
		buf := make([]byte, pktLen*2)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			rxSock.Fill(rxSock.FreeRxFrames())
			if _, err := rxSock.Poll(100 * time.Millisecond); err != nil {
				return
			}
			pkts := rxSock.ReceivePackets(64)
			for _, p := range pkts {
				n := rxSock.CopyOut(p, buf)
				if n == pktLen && buf[12] == 0x88 && buf[13] == 0xb5 {
					cp := append(Packet(nil), p...)
					// Copy the bytes out before recycling the frames.
					flat := append([]byte(nil), buf[:n]...)
					rxSock.RecyclePackets(pkts)
					if !bytes.Equal(flat, want) {
						t.Errorf("reassembled packet differs from what was sent")
					}
					got <- cp
					return
				}
			}
			rxSock.RecyclePackets(pkts)
		}
		close(got)
	}()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		n, err := txSock.SendBatch([][]byte{want})
		if err != nil {
			t.Fatalf("SendBatch: %v", err)
		}
		if n == 1 {
			break
		}
	}

	select {
	case p, ok := <-got:
		if !ok {
			t.Fatal("jumbo packet never arrived")
		}
		if len(p) < 2 {
			t.Errorf("packet arrived as %d fragment(s), want a multi-fragment chain "+
				"(%d bytes over %d-byte frames)", len(p), pktLen, frameSize)
		}
		if p.Len() != pktLen {
			t.Errorf("Packet.Len() = %d, want %d", p.Len(), pktLen)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("timed out waiting for the jumbo packet")
	}
}

// TestSendBatchOversizedWithoutMultiBuffer pins the non-multi-buffer contract:
// an oversized payload is an error, never a silent truncation on the wire.
func TestSendBatchOversizedWithoutMultiBuffer(t *testing.T) {
	ifA, ifB := newVethPair(t)
	tx, _ := openVethFleets(t, ifA, ifB, WithFrameSize(2048))
	txSock := tx.Sockets()[0]

	if txSock.multiBuffer() {
		t.Fatal("socket bound with XDP_USE_SG without WithMultiBuffer")
	}
	n, err := txSock.SendBatch([][]byte{make([]byte, 4096)})
	if err == nil {
		t.Fatal("SendBatch accepted a payload larger than FrameSize")
	}
	if n != 0 {
		t.Errorf("SendBatch queued %d packets alongside an error, want 0", n)
	}

	// Single-frame packets must still group one-per-Packet through the
	// multi-buffer reader, so ReceivePackets is safe to use unconditionally.
	if got := txSock.ReceivePackets(8); len(got) != 0 {
		t.Errorf("ReceivePackets on an idle tx socket returned %d packets", len(got))
	}
}

// TestSendBatchChainTooLong pins the multi-buffer transmit ceiling: a payload
// needing more frames than a packet may span is an error, not a chain the
// kernel will silently refuse.
func TestSendBatchChainTooLong(t *testing.T) {
	ifA, ifB := newVethPair(t)
	setMTU(t, 9000, ifA, ifB)
	const frameSize = 2048
	tx, _ := openVethFleets(t, ifA, ifB, WithMultiBuffer(), WithFrameSize(frameSize))
	txSock := tx.Sockets()[0]

	if !txSock.multiBuffer() {
		t.Fatal("WithMultiBuffer did not set XDP_USE_SG")
	}

	// One frame past the limit.
	tooBig := make([]byte, frameSize*(maxTxSegs+1))
	n, err := txSock.SendBatch([][]byte{tooBig})
	if err == nil {
		t.Fatalf("SendBatch accepted a payload spanning %d frames, limit is %d",
			maxTxSegs+1, maxTxSegs)
	}
	if n != 0 {
		t.Errorf("SendBatch queued %d packets alongside an error, want 0", n)
	}

	// Exactly at the limit must still be accepted, so the check is a ceiling
	// and not an off-by-one that rejects legal chains.
	atLimit := make([]byte, frameSize*maxTxSegs)
	if _, err := txSock.SendBatch([][]byte{atLimit}); err != nil {
		t.Errorf("SendBatch rejected a payload spanning exactly %d frames: %v", maxTxSegs, err)
	}
}

// TestVethEndToEnd sends packets across a veth pair through the full
// high-level API (Open, SendBatch, Poll/Receive/Recycle) in generic mode with
// need-wakeup enabled, and checks delivery and the kick counters.
func TestVethEndToEnd(t *testing.T) {
	ifA, ifB := newVethPair(t)
	tx, rx := openVethFleets(t, ifA, ifB, WithNeedWakeup())

	const numPackets = 1000
	frame := testFrame()
	batch := make([][]byte, 50)
	for i := range batch {
		batch[i] = frame
	}

	txSock, rxSock := tx.Sockets()[0], rx.Sockets()[0]
	done := make(chan int, 1)
	go func() { done <- receiveCount(rxSock, numPackets, time.Now().Add(10*time.Second)) }()

	sent := 0
	for sent < numPackets {
		want := numPackets - sent
		if want > len(batch) {
			want = len(batch)
		}
		n, err := txSock.SendBatch(batch[:want])
		if err != nil {
			t.Fatalf("SendBatch: %v", err)
		}
		sent += n
	}

	if got := <-done; got != numPackets {
		t.Fatalf("received %d of %d packets", got, numPackets)
	}
	// The kernel publishes the tx ring consumer index lazily (a syscall behind
	// its actual progress), so Stats.Transmitted can trail until the next
	// syscall touches the ring. One extra kick on the now-empty ring makes the
	// kernel publish before we assert.
	if err := txSock.Kick(); err != nil {
		t.Fatalf("kick: %v", err)
	}
	stats, err := txSock.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Transmitted != numPackets {
		t.Errorf("Transmitted = %d, want %d", stats.Transmitted, numPackets)
	}
	if stats.Kicks == 0 {
		t.Error("Kicks = 0: copy mode must issue kick syscalls")
	}
	if stats.KicksSuppressed != 0 {
		t.Errorf("KicksSuppressed = %d: copy mode keeps need-wakeup set, nothing should be suppressed", stats.KicksSuppressed)
	}

	// The receiver blocked in Poll for every batch, so its poll counter must
	// have moved and the derived packets-per-poll must be sane.
	rxStats, err := rxSock.Stats()
	if err != nil {
		t.Fatalf("rx stats: %v", err)
	}
	if rxStats.Polls == 0 {
		t.Error("Polls = 0 on a receiver that blocked in Poll")
	}
	if pp := rxStats.PacketsPerPoll(); pp <= 0 {
		t.Errorf("PacketsPerPoll() = %v, want > 0 with %d packets over %d polls",
			pp, rxStats.Received, rxStats.Polls)
	}
}

// TestPollWithCountsPolls is the regression test for a counter that only
// instrumented Poll: a consumer that waits through PollWith (because it needs
// to watch extra fds alongside the xsk) reported Polls=0 forever, so
// PacketsPerPoll read as "never blocked" on exactly the multi-queue shape
// where receive batching matters most.
func TestPollWithCountsPolls(t *testing.T) {
	ifA, ifB := newVethPair(t)
	_, rx := openVethFleets(t, ifA, ifB)
	xsk := rx.Sockets()[0]

	// Fill so PollWith actually blocks rather than taking its empty-fill-ring
	// early-out (which correctly makes no syscall and must not be counted).
	xsk.Fill(xsk.NumFreeFillSlots())

	before, err := xsk.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := xsk.PollWith(nil, 50*time.Millisecond); err != nil {
			t.Fatalf("PollWith: %v", err)
		}
	}
	after, err := xsk.Stats()
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if got := after.Polls - before.Polls; got != 3 {
		t.Errorf("PollWith made 3 blocking waits but Polls moved by %d, want 3", got)
	}
}

// TestPollEarlyOutNotCounted checks the other half of the contract: with an
// empty fill ring and an awake driver, both Poll and PollWith return without
// making a syscall, so neither may bump the counter. Runs against a bare
// Socket because a bound one has its fill ring populated before bind, and
// draining it just to reach this path would prove less.
func TestPollEarlyOutNotCounted(t *testing.T) {
	xsk := &Socket{fd: -1, wakeFd: -1} // numFilled 0, nil ring flags = driver awake

	if n, err := xsk.Poll(10 * time.Millisecond); n != 0 || err != nil {
		t.Fatalf("Poll early-out returned (%d, %v), want (0, nil)", n, err)
	}
	if ready, err := xsk.PollWith(nil, 10*time.Millisecond); !ready || err != nil {
		t.Fatalf("PollWith early-out returned (%v, %v), want (true, nil)", ready, err)
	}
	if got := xsk.statPolls.Load(); got != 0 {
		t.Errorf("Polls = %d after two no-syscall early-outs, want 0", got)
	}
}

// readNAPI returns an interface's two NAPI tuning values.
func readNAPI(t *testing.T, iface string) (string, string) {
	t.Helper()
	d, err := readSysfs(iface, "napi_defer_hard_irqs")
	if err != nil {
		t.Skipf("napi_defer_hard_irqs unavailable: %v", err)
	}
	g, err := readSysfs(iface, "gro_flush_timeout")
	if err != nil {
		t.Skipf("gro_flush_timeout unavailable: %v", err)
	}
	return d, g
}

// TestNAPITuning covers the apply/restore cycle and the refcount that keeps two
// overlapping fleets on one interface from stranding the host's settings.
func TestNAPITuning(t *testing.T) {
	ifA, _ := newVethPair(t)
	origDefer, origGRO := readNAPI(t, ifA)

	tuning := applyNAPITuning(ifA, 3, 250*time.Microsecond)
	if tuning == nil {
		t.Skip("cannot write NAPI sysfs attributes here")
	}
	gotDefer, gotGRO := readNAPI(t, ifA)
	if gotDefer != "3" || gotGRO != "250000" {
		t.Errorf("after apply: defer=%q gro=%q, want 3 and 250000", gotDefer, gotGRO)
	}

	// A second user must not re-save the already-tuned values as "original",
	// and must not restore while the first is still running.
	second := applyNAPITuning(ifA, 3, 250*time.Microsecond)
	second.restore()
	if d, g := readNAPI(t, ifA); d != "3" || g != "250000" {
		t.Errorf("first user still open but settings changed to defer=%q gro=%q", d, g)
	}

	tuning.restore()
	if d, g := readNAPI(t, ifA); d != origDefer || g != origGRO {
		t.Errorf("after restore: defer=%q gro=%q, want originals %q and %q", d, g, origDefer, origGRO)
	}
}

// TestGenericModeNotTuned is the regression test for the decision that only
// native-mode NICs are auto-tuned. These are host-wide settings, so running the
// test suite (or anything on veth) must leave the machine exactly as it found
// it.
func TestGenericModeNotTuned(t *testing.T) {
	ifA, ifB := newVethPair(t)
	beforeDefer, beforeGRO := readNAPI(t, ifB)

	_, rx := openVethFleets(t, ifA, ifB) // generic mode
	afterDefer, afterGRO := readNAPI(t, ifB)
	if afterDefer != beforeDefer || afterGRO != beforeGRO {
		t.Errorf("Open on a generic-mode interface changed NAPI settings: defer %q->%q, gro %q->%q",
			beforeDefer, afterDefer, beforeGRO, afterGRO)
	}
	if info, err := rx.Info(); err == nil && info.Tuning != "untuned" {
		t.Errorf("Info.Tuning = %q on a generic-mode fleet, want %q", info.Tuning, "untuned")
	}
}

// TestPacketsPerPoll covers the derived ratio without needing a socket.
func TestPacketsPerPoll(t *testing.T) {
	if got := (Stats{Received: 100, Polls: 0}).PacketsPerPoll(); got != 0 {
		t.Errorf("PacketsPerPoll() = %v with no polls yet, want 0", got)
	}
	if got := (Stats{Received: 1000, Polls: 10}).PacketsPerPoll(); got != 100 {
		t.Errorf("PacketsPerPoll() = %v, want 100", got)
	}
}

// ipFrame builds an Ethernet+IPv4 frame carrying a TCP or UDP header with the
// given ports, addressed to dstIP. Only the fields the XDP filter reads are
// meaningful; nothing here has to be a valid packet on the wire.
func ipFrame(proto uint8, srcPort, dstPort uint16, dstIP netip.Addr) []byte {
	f := make([]byte, 60)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	f[12], f[13] = 0x08, 0x00 // IPv4
	f[14] = 0x45              // version 4, 5-word header (no options)
	f[23] = proto
	src := netip.MustParseAddr("10.99.99.99").As4()
	dst := dstIP.As4()
	copy(f[26:30], src[:])
	copy(f[30:34], dst[:])
	binary.BigEndian.PutUint16(f[34:], srcPort)
	binary.BigEndian.PutUint16(f[36:], dstPort)
	return f
}

// ip6Frame is ipFrame for IPv6: Ethernet + a fixed 40-byte IPv6 header (no
// extension headers) + L4 ports.
func ip6Frame(proto uint8, srcPort, dstPort uint16, dstIP netip.Addr) []byte {
	f := make([]byte, 78)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	f[12], f[13] = 0x86, 0xdd // IPv6
	f[14] = 0x60              // version 6
	f[20] = proto             // next header
	src := netip.MustParseAddr("fd00:99::99").As16()
	dst := dstIP.As16()
	copy(f[22:38], src[:])
	copy(f[38:54], dst[:])
	binary.BigEndian.PutUint16(f[54:], srcPort)
	binary.BigEndian.PutUint16(f[56:], dstPort)
	return f
}

// arpFrame builds a minimal ARP frame (only the EtherType is inspected).
func arpFrame() []byte {
	f := make([]byte, 60)
	for i := 0; i < 6; i++ {
		f[i] = 0xff
	}
	f[12], f[13] = 0x08, 0x06 // ARP
	return f
}

// TestKeepManagement is the test that matters for WithKeepManagement: with
// MatchAll() the sockets must receive everything EXCEPT the traffic that keeps
// the box reachable, and without the option they must receive all of it. The
// negative half is what makes this meaningful — it fails if the exception
// blocks silently stop being emitted.
func TestKeepManagement(t *testing.T) {
	ifA, ifB := newVethPair(t)

	// Give the receiving end two IPv4 and two IPv6 addresses: the port
	// exceptions are scoped to the interface's own addresses, and a dual-stack
	// host with several of each is the case worth proving.
	linkB, err := netlink.LinkByName(ifB)
	if err != nil {
		t.Fatalf("look up %s: %v", ifB, err)
	}
	local := netip.MustParseAddr("10.99.42.1")   // first IPv4
	local2 := netip.MustParseAddr("10.99.43.1")  // second IPv4
	local6 := netip.MustParseAddr("fd00:42::1")  // first IPv6
	local62 := netip.MustParseAddr("fd00:43::1") // second IPv6
	for _, cidr := range []string{
		local.String() + "/24", local2.String() + "/24",
		local6.String() + "/64", local62.String() + "/64",
	} {
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatalf("parse addr %s: %v", cidr, err)
		}
		// NODAD: an IPv6 address stays tentative for a second or so otherwise,
		// which would race the fleet opening below.
		addr.Flags |= unix.IFA_F_NODAD
		if err := netlink.AddrAdd(linkB, addr); err != nil {
			t.Skipf("cannot add %s to %s: %v", cidr, ifB, err)
		}
	}

	// Each probe is (name, frame, wantRedirectedWithKeepManagement).
	probes := []struct {
		name  string
		bytes []byte
		want  bool // true = should reach AF_XDP even with WithKeepManagement
	}{
		{"v4-ssh-inbound", ipFrame(ipProtoTCP, 40000, 22, local), false},
		{"v4-ssh-inbound-2nd-addr", ipFrame(ipProtoTCP, 40000, 22, local2), false},
		{"v4-ssh-return", ipFrame(ipProtoTCP, 22, 40000, local), false},
		{"v4-dns-reply-udp", ipFrame(ipProtoUDP, 53, 40000, local), false},
		{"v4-dns-reply-tcp", ipFrame(ipProtoTCP, 53, 40000, local), false},
		{"v6-ssh-inbound", ip6Frame(ipProtoTCP, 40000, 22, local6), false},
		{"v6-ssh-inbound-2nd-addr", ip6Frame(ipProtoTCP, 40000, 22, local62), false},
		{"v6-ssh-return", ip6Frame(ipProtoTCP, 22, 40000, local6), false},
		{"v6-dns-reply-udp", ip6Frame(ipProtoUDP, 53, 40000, local6), false},
		{"arp", arpFrame(), false},
		// Transit traffic on port 22 is NOT ours, so it must still be captured:
		// this is what scoping to the local addresses buys on a router.
		{"v4-ssh-to-someone-else", ipFrame(ipProtoTCP, 40000, 22, netip.MustParseAddr("10.99.42.77")), true},
		{"v6-ssh-to-someone-else", ip6Frame(ipProtoTCP, 40000, 22, netip.MustParseAddr("fd00:42::77")), true},
		{"v4-ordinary-udp", ipFrame(ipProtoUDP, 40000, 9999, local), true},
		{"v6-ordinary-udp", ip6Frame(ipProtoUDP, 40000, 9999, local6), true},
	}

	// run sends every probe once and reports which ones reached the sockets.
	run := func(t *testing.T, keepManagement bool) map[string]bool {
		t.Helper()
		rxOpts := []Option{WithGenericMode(), WithFilter(MatchAll())}
		if keepManagement {
			rxOpts = append(rxOpts, WithKeepManagement())
		}
		tx, err := Open(ifA, WithGenericMode(), WithFilter(MatchNone()))
		if err != nil {
			t.Fatalf("open tx: %v", err)
		}
		defer tx.Close()
		rx, err := Open(ifB, rxOpts...)
		if err != nil {
			t.Fatalf("open rx: %v", err)
		}
		defer rx.Close()
		if !tx.WaitLinkUp(5 * time.Second) {
			t.Fatal("veth link did not come up")
		}
		txSock, rxSock := tx.Sockets()[0], rx.Sockets()[0]

		// Send each probe several times: a veth carries unrelated kernel
		// traffic, and one lost frame should not decide the result.
		for i := 0; i < 5; i++ {
			for _, p := range probes {
				if _, err := txSock.SendBatch([][]byte{p.bytes}); err != nil {
					t.Fatalf("send %s: %v", p.name, err)
				}
			}
		}

		got := map[string]bool{}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			rxSock.Fill(rxSock.NumFreeFillSlots())
			n, err := rxSock.Poll(200 * time.Millisecond)
			if err != nil || n == 0 {
				continue
			}
			descs := rxSock.Receive(n)
			for _, d := range descs {
				frame := rxSock.GetFrame(d)
				for _, p := range probes {
					if len(frame) >= len(p.bytes) && string(frame[:len(p.bytes)]) == string(p.bytes) {
						got[p.name] = true
					}
				}
			}
			rxSock.Recycle(descs)
		}
		return got
	}

	// A VLAN sub-interface with its own address: the XDP program attaches to
	// the parent, so an address that only exists on the child must still be
	// protected. This is the common shape for a box managed over a tagged VLAN,
	// where the parent holds nothing but a link-local address.
	vlanIP := netip.MustParseAddr("10.99.44.1")
	vlan := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Name: ifB + ".77", ParentIndex: linkB.Attrs().Index},
		VlanId:    77,
	}
	if err := netlink.LinkAdd(vlan); err != nil {
		t.Skipf("cannot create vlan sub-interface: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(vlan) })
	vaddr, err := netlink.ParseAddr(vlanIP.String() + "/24")
	if err != nil {
		t.Fatalf("parse vlan addr: %v", err)
	}
	if err := netlink.AddrAdd(vlan, vaddr); err != nil {
		t.Fatalf("add vlan addr: %v", err)
	}
	if err := netlink.LinkSetUp(vlan); err != nil {
		t.Fatalf("set vlan up: %v", err)
	}
	probes = append(probes, struct {
		name  string
		bytes []byte
		want  bool
	}{"v4-ssh-to-vlan-subif-addr", ipFrame(ipProtoTCP, 40000, 22, vlanIP), false})

	t.Run("without", func(t *testing.T) {
		got := run(t, false)
		// Plain MatchAll must capture everything, management traffic included.
		for _, p := range probes {
			if !got[p.name] {
				t.Errorf("%s: not captured by plain MatchAll(); the probe or test rig is wrong, "+
					"which would make the WithKeepManagement half meaningless", p.name)
			}
		}
	})

	t.Run("with", func(t *testing.T) {
		got := run(t, true)
		for _, p := range probes {
			switch {
			case p.want && !got[p.name]:
				t.Errorf("%s: should have been captured but was passed to the kernel", p.name)
			case !p.want && got[p.name]:
				t.Errorf("%s: should have been left for the kernel but was captured — "+
					"this is the lockout case WithKeepManagement exists to prevent", p.name)
			}
		}
	})
}

// TestSendValidation covers the SendBatch/SendFunc error paths: oversized
// payloads and lying build callbacks are rejected without queueing or leaking
// frames, and a closed socket reports net.ErrClosed.
func TestSendValidation(t *testing.T) {
	ifA, ifB := newVethPair(t)
	tx, _ := openVethFleets(t, ifA, ifB)
	xsk := tx.Sockets()[0]

	t.Run("oversized payload", func(t *testing.T) {
		big := make([]byte, xsk.FrameSize()+1)
		n, err := xsk.SendBatch([][]byte{testFrame(), big})
		if err == nil {
			t.Fatalf("oversized payload accepted, queued %d", n)
		}
		if n != 0 {
			t.Errorf("queued %d packets from a rejected batch, want 0", n)
		}
	})

	t.Run("bad build length", func(t *testing.T) {
		before := xsk.FreeTxFrames()
		n, err := xsk.SendFunc(4, func(i int, f []byte) int { return len(f) + 1 })
		if err == nil {
			t.Fatalf("bad build length accepted, queued %d", n)
		}
		if after := xsk.FreeTxFrames(); after != before {
			t.Errorf("tx pool %d after aborted SendFunc, want %d (frames leaked)", after, before)
		}
	})

	t.Run("closed socket", func(t *testing.T) {
		ifC, ifD := newVethPair(t)
		tx2, _ := openVethFleets(t, ifC, ifD)
		xsk2 := tx2.Sockets()[0]
		tx2.Close()
		if _, err := xsk2.SendFunc(1, func(i int, f []byte) int { return 0 }); !errors.Is(err, net.ErrClosed) {
			t.Errorf("SendFunc on closed socket: err = %v, want net.ErrClosed", err)
		}
	})
}

// TestKickDrainsLargeBatch is the regression test for the Kick EAGAIN drain
// loop. The kernel's copy-mode transmit only processes a bounded batch of
// descriptors per sendto (TX_BATCH_SIZE, 32 in current kernels), so a single
// Transmit of many more than that relies on Kick retrying while the kernel
// makes progress. Without the drain, the excess descriptors sit on the tx ring
// with no completions until some later kick — which this test never issues.
func TestKickDrainsLargeBatch(t *testing.T) {
	ifA, ifB := newVethPair(t)
	tx, _ := openVethFleets(t, ifA, ifB)
	xsk := tx.Sockets()[0]

	const batch = 256
	frame := testFrame()
	descs := xsk.Alloc(batch)
	if len(descs) != batch {
		t.Fatalf("Alloc returned %d frames, want %d", len(descs), batch)
	}
	for i := range descs {
		descs[i].Len = uint32(copy(xsk.GetFrame(descs[i])[:len(frame)], frame))
	}
	if n := xsk.Transmit(descs); n != batch {
		t.Fatalf("Transmit queued %d, want %d", n, batch)
	}

	// Only reap completions from here on — no further kicks. Every descriptor
	// must complete off the back of Transmit's own kick.
	reclaimed := 0
	deadline := time.Now().Add(3 * time.Second)
	for reclaimed < batch && time.Now().Before(deadline) {
		reclaimed += xsk.Complete(xsk.NumCompleted())
		time.Sleep(time.Millisecond)
	}
	if reclaimed != batch {
		t.Fatalf("only %d of %d descriptors completed after one Transmit — kick did not drain the ring", reclaimed, batch)
	}
}

// TestNamespacedVeth runs the low-level API (NewSocket, NewProgram) on a veth
// pair inside a fresh network namespace, leaving the host untouched. Open
// cannot be used here — it counts queues via /sys/class/net, which still shows
// the host namespace — but sockets, binds, and BPF attach all resolve
// interfaces in the calling thread's namespace, so the core datapath is fully
// testable in isolation.
func TestNamespacedVeth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create network namespaces")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock (need privileges): %v", err)
	}

	// Namespace membership is per OS thread; keep this goroutine pinned so
	// every netlink/bpf/socket call below happens inside the new namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Skipf("cannot get current netns: %v", err)
	}
	defer orig.Close()
	ns, err := netns.New() // creates the namespace and enters it
	if err != nil {
		t.Skipf("cannot create netns: %v", err)
	}
	defer func() {
		_ = netns.Set(orig)
		ns.Close()
	}()

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "vtha"}, PeerName: "vthb"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth in netns: %v", err)
	}
	var ifindex [2]int
	for i, name := range []string{"vtha", "vthb"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("set %s up: %v", name, err)
		}
		ifindex[i] = l.Attrs().Index
	}

	// Receive side on vthb: redirect-all program plus one socket on queue 0.
	prog, err := NewProgram(1)
	if err != nil {
		t.Fatalf("NewProgram: %v", err)
	}
	defer prog.Close()
	if err := prog.Attach(ifindex[1], XDPFlagsSkbMode); err != nil {
		t.Fatalf("attach in netns: %v", err)
	}
	defer prog.Detach(ifindex[1])
	rxSock, err := NewSocket(ifindex[1], 0, nil)
	if err != nil {
		t.Fatalf("rx NewSocket in netns: %v", err)
	}
	defer rxSock.Close()
	if err := prog.Register(0, rxSock.FD()); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Transmit side on vtha: copy-mode TX needs no program.
	txSock, err := NewSocket(ifindex[0], 0, nil)
	if err != nil {
		t.Fatalf("tx NewSocket in netns: %v", err)
	}
	defer txSock.Close()

	const numPackets = 100
	frame := testFrame()
	sent := 0
	deadline := time.Now().Add(5 * time.Second)
	for sent < numPackets && time.Now().Before(deadline) {
		n, err := txSock.SendBatch([][]byte{frame, frame, frame, frame})
		if err != nil {
			t.Fatalf("SendBatch: %v", err)
		}
		sent += n
	}
	if got := receiveCount(rxSock, sent, time.Now().Add(5*time.Second)); got < sent {
		t.Fatalf("received %d of %d packets in netns", got, sent)
	}
}
