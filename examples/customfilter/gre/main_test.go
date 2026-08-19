//go:build linux

// This test is half the point of the example. A hand-written eBPF matcher
// fails silently — a wrong offset or a missed byte swap still verifies, still
// attaches, and matches the wrong packets — so the only way to trust one is to
// run it against packets you built on purpose.
//
// afxdp.MatchPacket assembles the same eBPF Open would attach and executes it
// in the kernel with BPF_PROG_TEST_RUN, so this needs no NIC and no traffic:
//
//	go test ./examples/customfilter/gre        # needs CAP_BPF + CAP_NET_ADMIN
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// greFrame builds an Ethernet/IPv4/GRE frame. flags is the raw 16-bit GRE flags
// field; key is written whether or not the K bit says it is there, so a test
// can check that the flags are actually being honoured.
func greFrame(src, dst string, flags uint16, key uint32) []byte {
	b := []byte{
		0x02, 0, 0, 0, 0, 0x01, // dst MAC
		0x02, 0, 0, 0, 0, 0x02, // src MAC
		0x08, 0x00, // EtherType: IPv4
	}
	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, IHL 5 (no options)
	binary.BigEndian.PutUint16(ip[2:], 20+12)
	ip[8], ip[9] = 64, greProto
	copy(ip[12:], net.ParseIP(src).To4())
	copy(ip[16:], net.ParseIP(dst).To4())

	gre := make([]byte, 12)
	binary.BigEndian.PutUint16(gre[0:], flags)
	binary.BigEndian.PutUint16(gre[2:], 0x0800) // inner protocol: IPv4
	binary.BigEndian.PutUint32(gre[4:], key)

	return append(append(b, ip...), gre...)
}

// nonGREFrame is a plain IPv4/UDP frame, to prove the protocol check bites.
func nonGREFrame() []byte {
	b := []byte{0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00}
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 17 // UDP
	binary.BigEndian.PutUint16(ip[2:], 28)
	copy(ip[12:], net.ParseIP("192.0.2.1").To4())
	copy(ip[16:], net.ParseIP("192.0.2.2").To4())
	return append(append(b, ip...), make([]byte, 8)...)
}

// requireBPF establishes once whether this environment can load and run BPF at
// all, and skips the test if not. The capability decision is made HERE, not
// per case: past this point any MatchPacket error is a real failure, so a
// broken matcher cannot report green through a skip.
func requireBPF(t *testing.T) {
	t.Helper()
	probeOnce.Do(func() {
		if err := rlimit.RemoveMemlock(); err != nil {
			probeErr = fmt.Errorf("cannot raise memlock: %w", err)
			return
		}
		if _, err := afxdp.MatchPacket(make([]byte, 14),
			afxdp.WithFilter(afxdp.MatchUDPPort(5000))); err != nil {
			probeErr = fmt.Errorf("cannot load and run BPF here: %w", err)
		}
	})
	if probeErr != nil {
		t.Skipf("skipping: %v", probeErr)
	}
}

var (
	probeOnce sync.Once
	probeErr  error
)

func TestMatchGREKey(t *testing.T) {
	requireBPF(t)

	const wanted = 42
	m := matchGREKey(wanted)

	// Every hit is paired with a near miss — the same frame with one field
	// changed. A matcher only ever shown packets it should accept looks correct
	// right up until it ships.
	for _, tc := range []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"right key", greFrame("192.0.2.1", "192.0.2.2", greFlagKey, wanted), true},
		{"wrong key", greFrame("192.0.2.1", "192.0.2.2", greFlagKey, 43), false},
		{"no K flag", greFrame("192.0.2.1", "192.0.2.2", 0, wanted), false},
		// C set means a checksum precedes the key, so offset 38 is not the key
		// at all. Documented as not matching; this proves it.
		{"C flag set", greFrame("192.0.2.1", "192.0.2.2", greFlagKey|greFlagChecksum, wanted), false},
		{"not GRE", nonGREFrame(), false},
		{"runt", make([]byte, 14), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := afxdp.MatchPacket(tc.pkt, afxdp.WithFilter(m))
			if err != nil {
				// requireBPF proved the environment works, so any error here
				// is real. Unwrap the verifier form for its program listing.
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("filter rejected by the verifier:\n%+v", ve)
				}
				t.Fatalf("MatchPacket: %v", err)
			}
			if got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMatchGREKeyHighBit checks the Imm32 choice directly. A key above
// 0x7fffffff is the case that would break with .Imm: the expected value
// sign-extends to a negative number while the packet load zero-extends, so the
// two never compare equal and the matcher silently never fires.
func TestMatchGREKeyHighBit(t *testing.T) {
	requireBPF(t)
	const key = 0xdeadbeef
	m := matchGREKey(key)
	for _, tc := range []struct {
		name string
		key  uint32
		want bool
	}{
		{"exact", key, true},
		{"off by one", key - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := afxdp.MatchPacket(
				greFrame("192.0.2.1", "192.0.2.2", greFlagKey, tc.key),
				afxdp.WithFilter(m))
			if err != nil {
				t.Fatalf("MatchPacket: %v", err)
			}
			if got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}
