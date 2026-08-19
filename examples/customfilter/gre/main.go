//go:build linux

// gre captures one GRE tunnel by its key — the case that motivated the
// low-level API in the first place (issue #9): a field no built-in matcher
// reaches, matched in the kernel rather than in your receive loop.
//
//	go build -o gre ./examples/customfilter/gre
//	sudo ./gre -iface eth0 -key 42
//
// The built-ins get you as far as "all GRE" (MatchIPv4Proto(47)); a tcpdump
// expression gets you further. This goes the last step, and it is the example
// to read if you want to see the whole low-level story in one place:
//
//   - a custom Match assembled from the exported API alone (MatchEnv,
//     FrameBase, Bounds, Label, NetShort, OffEtherType)
//   - argument validation reported through MatchError, so Open surfaces it
//   - and a unit test, in main_test.go, that runs the matcher against crafted
//     packets with afxdp.MatchPacket — no NIC, no traffic, no root NIC setup
//
// That last part matters more than it sounds. Hand-written eBPF fails
// silently: a wrong offset or a missed byte swap still verifies, still
// attaches, and simply matches the wrong packets. MatchPacket is how you find
// that out at "go test" time instead of in production.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// GRE (RFC 2784 + RFC 2890) sits directly on IP as protocol 47. Its header is
// 2 bytes of flags, 2 bytes of inner protocol type, and then whichever optional
// fields the flags announce, in a fixed order: checksum, key, sequence.
const (
	greProto = 47

	offGREFlags = 34 // 14 Ethernet + 20 IPv4 (no options)
	offGREKey   = 38 // flags(2) + protocol(2), with C clear so no checksum first

	greFlagChecksum = 0x8000 // C: a 4-byte checksum+reserved precedes the key
	greFlagKey      = 0x2000 // K: the 4-byte key is present
)

// matchGREKey matches IPv4 GRE packets carrying the given key.
//
// It requires the K flag set and the C flag clear, which puts the key at a
// fixed offset. With C also set the checksum field pushes the key four bytes
// further along; handling both would mean a branch, and the point here is to
// stay readable. Packets with C set simply do not match — stated plainly rather
// than silently mismatched.
func matchGREKey(key uint32) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("gre-key/%d", key), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		// One bounds check covering the furthest byte read: the key ends at 42.
		ins = append(ins, e.Bounds(frame, offGREKey+4)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte), // IPv4 protocol
			asm.JNE.Imm(asm.R3, greProto, e.Next),

			// Flags are a 16-bit big-endian field, so mask and value both go
			// through NetShort — the same rule as any multi-byte compare.
			asm.LoadMem(asm.R3, frame, offGREFlags, asm.Half),
			asm.And.Imm(asm.R3, afxdp.NetShort(greFlagKey|greFlagChecksum)),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(greFlagKey), e.Next),

			// The key is 32 bits, so this needs Imm32: the .Imm forms compare
			// 64 bits, and a key with its high bit set would be sign-extended
			// to a negative number and never match.
			asm.LoadMem(asm.R3, frame, offGREKey, asm.Word),
			asm.JEq.Imm32(asm.R3, int32(keyLE(key)), e.Redirect),
		), nil
	})
}

// keyLE builds the expected key the way a little-endian 32-bit load sees it.
// Build the value the way the load sees it rather than swapping afterwards —
// that rule covers every width.
func keyLE(key uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], key)
	return binary.NativeEndian.Uint32(b[:])
}

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	key := flag.Uint("key", 42, "GRE key to capture")
	flag.Parse()

	if *key > 0xffffffff {
		log.Fatalf("key %d out of range (32-bit)", *key)
	}

	fleet, err := afxdp.Open(*iface,
		afxdp.WithFilter(matchGREKey(uint32(*key))),
		// See the header: keeps your SSH session with the kernel.
		afxdp.WithKeepManagement())
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("open %s: the filter was rejected by the kernel verifier:\n%+v", *iface, ve)
		}
		log.Fatalf("open %s: %v", *iface, err)
	}

	if info, err := fleet.Info(); err == nil {
		log.Printf("started: %s", info)
	}
	log.Printf("waiting for the link to come up...")
	if fleet.WaitLinkUp(15 * time.Second) {
		log.Printf("link up; waiting for matching packets (ctrl-c to stop)")
	} else {
		log.Printf("warning: link not up after 15s; continuing anyway")
	}

	for _, xsk := range fleet.Sockets() {
		go func(xsk *afxdp.Socket) {
			for {
				xsk.Fill(xsk.NumFreeFillSlots())
				n, err := xsk.Poll(-1)
				if err != nil {
					return
				}
				descs := xsk.Receive(n)
				for _, d := range descs {
					fmt.Println(summary(xsk.GetFrame(d)))
				}
				xsk.Recycle(descs)
			}
		}(xsk)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fleet.Close()
	log.Println("stopped")
}

// summary decodes the tunnel endpoints and the key the filter matched on.
func summary(f []byte) string {
	l3 := 14
	if len(f) >= 14 && binary.BigEndian.Uint16(f[12:]) == afxdp.EtherTypeVLAN {
		l3 = 18
	}
	gre := l3 + 20
	if len(f) < gre+8 {
		return fmt.Sprintf("%d bytes (short)", len(f))
	}
	return fmt.Sprintf("%4d bytes  %s -> %s  gre key=%d inner=0x%04x", len(f),
		net.IP(f[l3+12:l3+16]), net.IP(f[l3+16:l3+20]),
		binary.BigEndian.Uint32(f[gre+4:]), binary.BigEndian.Uint16(f[gre+2:]))
}
