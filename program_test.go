//go:build linux

package afxdp

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestFilterProgramsVerify loads the hand-written XDP filter programs through
// the kernel BPF verifier. It needs CAP_BPF/CAP_SYS_ADMIN and locked-memory
// headroom, so it skips when run unprivileged or where BPF is unavailable
// (e.g. CI sandboxes). When it does run, a verifier rejection fails the test —
// that is the real check the assembly is well-formed for every Match builder
// and for composing them. Any other error is environmental and skips.
func TestFilterProgramsVerify(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot raise memlock (need privileges): %v", err)
	}
	// mgmt builds the WithKeepManagement exception set for a mixed-family host,
	// so the verifier checks every generated block including the IPv6 paths.
	mgmt := func(tcpPorts ...uint16) []Match {
		if len(tcpPorts) == 0 {
			tcpPorts = []uint16{22}
		}
		return managementExceptions([]netip.Prefix{
			netip.MustParsePrefix("192.168.1.5/32"),
			netip.MustParsePrefix("2001:db8::1/128"),
		}, tcpPorts, false)
	}
	cases := []struct {
		name       string
		matches    []Match
		exceptions []Match
	}{
		{"keep-management", []Match{MatchAll()}, mgmt()},
		{"keep-management-extra-port", []Match{MatchAll()}, mgmt(22, 2222)},
		{"keep-management-unscoped", []Match{MatchAll()}, managementExceptions(nil, []uint16{22}, true)},
		{"keep-management-arp-nd-only", []Match{MatchAll()}, managementExceptions(nil, []uint16{22}, false)},
		{"keep-management-dual-stack-2x2", []Match{MatchAll()}, managementExceptions([]netip.Prefix{
			netip.MustParsePrefix("192.168.1.5/32"),
			netip.MustParsePrefix("10.0.0.7/32"),
			netip.MustParsePrefix("2001:db8::1/128"),
			netip.MustParsePrefix("fd00::2/128"),
		}, []uint16{22}, false)},
		{"keep-management-with-filter", []Match{MatchUDPPort(4789), MatchICMPEcho()}, mgmt()},
		{"udp-two-ports", []Match{MatchUDPPort(4789, 51820)}, nil},
		{"udp-any", []Match{MatchUDPPort()}, nil},
		{"tcp-port", []Match{MatchTCPPort(443)}, nil},
		{"icmp-echo", []Match{MatchICMPEcho()}, nil},
		{"ip-proto-gre", []Match{MatchIPProto(47)}, nil},
		{"ethertype-arp", []Match{MatchEtherType(0x0806)}, nil},
		{"all", []Match{MatchAll()}, nil},
		{"none", []Match{MatchNone()}, nil},
		{"src-ip4", []Match{MatchSrcIP("10.0.0.0/8")}, nil},
		{"dst-ip4-host", []Match{MatchDstIP("192.168.1.5/32")}, nil},
		{"src-ip6", []Match{MatchSrcIP("2001:db8::/32")}, nil},
		{"dst-ip6-host", []Match{MatchDstIP("2001:db8::1/128")}, nil},
		{"ip-mixed", []Match{MatchSrcIP("10.0.0.0/8"), MatchDstIP("2001:db8::/48")}, nil},
		{"flow-v4", []Match{MatchFlow("10.0.0.1/32", "10.0.0.2/32")}, nil},
		{"flow-v6", []Match{MatchFlow("2001:db8::/32", "2001:db8:1::/48")}, nil},
		{"flow-both-dirs", []Match{MatchFlow("10.0.0.1/32", "10.0.0.2/32"), MatchFlow("10.0.0.2/32", "10.0.0.1/32")}, nil},
		{"composite", []Match{MatchUDPPort(4789, 51820), MatchICMPEcho(), MatchTCPPort(22), MatchSrcIP("172.16.0.0/12")}, nil},
	}
	// Every filter is loaded twice: once plain and once with
	// BPF_F_XDP_HAS_FRAGS. Under xdp.frags semantics data_end covers only the
	// linear head, so a filter that reached past it would verify plain and be
	// rejected here. Our matches only parse L2/L3/L4 headers, which always live
	// in the first fragment — this test is what keeps that true.
	for _, frags := range []bool{false, true} {
		suffix := ""
		if frags {
			suffix = "/frags"
		}
		for _, tc := range cases {
			t.Run(tc.name+suffix, func(t *testing.T) {
				prog, err := newFilterProgram(4, tc.exceptions, tc.matches, frags)
				if err != nil {
					var ve *ebpf.VerifierError
					if errors.As(err, &ve) {
						t.Fatalf("verifier rejected %s (frags=%v):\n%+v", tc.name, frags, ve)
					}
					t.Skipf("cannot load BPF program in this environment: %v", err)
				}
				prog.Close()
			})
		}
	}
}
