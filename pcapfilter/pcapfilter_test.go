//go:build linux

package pcapfilter_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/atoonk/go-afxdp"
	"github.com/atoonk/go-afxdp/pcapfilter"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func tcpFrame(src, dst string, sport, dport uint16) []byte {
	b := []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00}
	ip := make([]byte, 20)
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	copy(ip[12:], net.ParseIP(src).To4())
	copy(ip[16:], net.ParseIP(dst).To4())
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	t[12] = 5 << 4
	return append(append(b, ip...), t...)
}

// TestMatchExpressions runs real tcpdump expressions through libpcap, into
// bpfmatch.Match, and executes the result in the kernel. RFC 5737 addresses.
// requireBPF decides once whether this environment can load and run BPF, and
// skips if not. Past it, any MatchPacket error is a real failure — a per-case
// skip would let a broken libpcap->cBPF->eBPF translation report green.
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

func TestMatchExpressions(t *testing.T) {
	requireBPF(t)
	for _, tc := range []struct {
		expr string
		pkt  []byte
		want bool
	}{
		{"tcp port 22", tcpFrame("192.0.2.1", "192.0.2.2", 1234, 22), true},
		{"tcp port 22", tcpFrame("192.0.2.1", "192.0.2.2", 1234, 443), false},
		{"tcp port 22 and not src host 192.0.2.1", tcpFrame("192.0.2.1", "192.0.2.2", 1234, 22), false},
		{"tcp port 22 and not src host 192.0.2.1", tcpFrame("192.0.2.9", "192.0.2.2", 1234, 22), true},
		{"tcp dst port 443 or tcp dst port 22", tcpFrame("192.0.2.1", "192.0.2.2", 1, 443), true},
		{"net 198.51.100.0/24", tcpFrame("198.51.100.7", "192.0.2.2", 1, 9), true},
		{"net 198.51.100.0/24", tcpFrame("192.0.2.7", "192.0.2.2", 1, 9), false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			m, err := pcapfilter.Compile(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := afxdp.MatchPacket(tc.pkt, afxdp.WithFilter(m))
			if err != nil {
				// requireBPF proved the environment; any error here is real.
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("filter rejected:\n%+v", ve)
				}
				t.Fatalf("MatchPacket: %v", err)
			}
			if got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBadExpression checks a syntax error is reported, not attached.
func TestBadExpression(t *testing.T) {
	if _, err := pcapfilter.Compile("this is not a filter"); err == nil {
		t.Fatal("bad expression accepted")
	}
	// Match defers the error to the point of use, like the built-in builders.
	m := pcapfilter.Match("this is not a filter")
	if _, err := afxdp.MatchPacket(make([]byte, 60), afxdp.WithFilter(m)); err == nil {
		t.Error("Match with a bad expression did not fail at use")
	}
}
