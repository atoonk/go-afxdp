//go:build linux

package afxdp

import (
	"errors"
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
	cases := []struct {
		name    string
		matches []Match
	}{
		{"udp-two-ports", []Match{MatchUDPPort(4789, 51820)}},
		{"udp-any", []Match{MatchUDPPort()}},
		{"tcp-port", []Match{MatchTCPPort(443)}},
		{"icmp-echo", []Match{MatchICMPEcho()}},
		{"ip-proto-gre", []Match{MatchIPProto(47)}},
		{"ethertype-arp", []Match{MatchEtherType(0x0806)}},
		{"all", []Match{MatchAll()}},
		{"none", []Match{MatchNone()}},
		{"src-ip4", []Match{MatchSrcIP("10.0.0.0/8")}},
		{"dst-ip4-host", []Match{MatchDstIP("192.168.1.5/32")}},
		{"src-ip6", []Match{MatchSrcIP("2001:db8::/32")}},
		{"dst-ip6-host", []Match{MatchDstIP("2001:db8::1/128")}},
		{"ip-mixed", []Match{MatchSrcIP("10.0.0.0/8"), MatchDstIP("2001:db8::/48")}},
		{"flow-v4", []Match{MatchFlow("10.0.0.1/32", "10.0.0.2/32")}},
		{"flow-v6", []Match{MatchFlow("2001:db8::/32", "2001:db8:1::/48")}},
		{"flow-both-dirs", []Match{MatchFlow("10.0.0.1/32", "10.0.0.2/32"), MatchFlow("10.0.0.2/32", "10.0.0.1/32")}},
		{"composite", []Match{MatchUDPPort(4789, 51820), MatchICMPEcho(), MatchTCPPort(22), MatchSrcIP("172.16.0.0/12")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := newFilterProgram(4, tc.matches)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("verifier rejected %s:\n%+v", tc.name, ve)
				}
				t.Skipf("cannot load BPF program in this environment: %v", err)
			}
			prog.Close()
		})
	}
}
