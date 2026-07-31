//go:build linux

package afxdp

import (
	"errors"
	"fmt"
	"net"
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
