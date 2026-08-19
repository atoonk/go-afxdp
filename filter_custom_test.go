//go:build linux

// This file is deliberately in the external test package afxdp_test: it can
// only reach exported identifiers, so the fact that it compiles at all is the
// proof that a custom Match can be written from another package (issue #9).
package afxdp_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/atoonk/go-afxdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

// Offsets from the frame base returned by MatchEnv.FrameBase. Ethernet is 14
// bytes, and these assume an IPv4 header with no options (IHL=5), the same
// assumption the built-in matchers make.
const (
	offIPProto = 23 // 14 + 9
	offL4Dport = 36 // 14 + 20 + 2
)

// matchUDPDstPort is a custom reimplementation of MatchUDPPort built purely
// from the exported API. It doubles as the README example.
func matchUDPDstPort(port uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("custom-udp/%d", port), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, offL4Dport+2)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next), // UDP
			asm.LoadMem(asm.R3, frame, offL4Dport, asm.Half),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(port), e.Redirect),
		), nil
	})
}

// matchTCPDstPortViaLabel matches TCP on port, routing the hit through an
// explicit landing pad created with MatchEnv.Label. It exists to exercise
// Label and, used alongside matchUDPDstPort, to prove two custom matches in
// one program do not collide on symbol names.
func matchTCPDstPortViaLabel(port uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("custom-tcp/%d", port), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		hit := e.Label("hit")
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, offL4Dport+2)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, 6, e.Next), // TCP
			asm.LoadMem(asm.R3, frame, offL4Dport, asm.Half),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(port), hit),
			asm.Ja.Label(e.Next),
			asm.Mov.Reg(asm.R3, asm.R3).WithSymbol(hit), // landing pad
			asm.Ja.Label(e.Redirect),
		), nil
	})
}

// matchUnbounded loads a header field without calling Bounds first. The
// verifier must reject it: this is what makes MatchEnv.Bounds load-bearing
// rather than advisory.
func matchUnbounded() afxdp.Match {
	return afxdp.NewMatch("custom-unbounded", func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		return append(ins,
			asm.LoadMem(asm.R3, frame, offL4Dport, asm.Half),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(5000), e.Redirect),
		), nil
	})
}

// --- copies of the matchers shipped in examples/customfilter ---------------
//
// Each example under examples/customfilter carries its own matcher in its
// main.go (vlan, udpsrcport, tcpsyn, vxlan, dstmac); these are copies,
// kept in sync by hand rather than shared, because an example should be
// readable standalone. They are tested here because the byte-order arithmetic
// is what a reader is most likely to copy and least likely to notice breaking:
// every multi-byte compare is against a little-endian load, so the expected
// value has to be built the way that load sees it. A mistake there still
// verifies and still matches something, so it fails silently.
//
// If you change one of these, change the matching example too.

// matchVLAN matches frames carrying an 802.1Q tag with the given VLAN ID.
// The tag is only visible from the raw frame start: FrameBase steps over it.
func matchVLAN(vid uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("vlan/%d", vid), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins := e.Bounds(e.Data, 16)
		return append(ins,
			asm.LoadMem(asm.R3, e.Data, 12, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeVLAN), e.Next),
			// The VID is the low 12 bits of the big-endian TCI, so both the
			// mask and the value get the NetShort treatment.
			asm.LoadMem(asm.R3, e.Data, 14, asm.Half),
			asm.And.Imm(asm.R3, afxdp.NetShort(0x0fff)),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(vid), e.Redirect),
		), nil
	})
}

// matchUDPSrcPort matches IPv4/UDP by *source* port, which no built-in does.
func matchUDPSrcPort(port uint16) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("udp-src/%d", port), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, 34+2)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next),
			asm.LoadMem(asm.R3, frame, 34, asm.Half), // UDP source port
			asm.JEq.Imm(asm.R3, afxdp.NetShort(port), e.Redirect),
		), nil
	})
}

// TCP flag bits, as they sit in the single byte at offset 13 of the TCP header.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpACK = 0x10
)

// matchTCPFlags matches IPv4/TCP whose flags byte, masked with mask, equals
// value. Parameterised exactly as the tcpsyn example is, so both the SYN and
// the SYN+ACK rule that example can install are covered here.
func matchTCPFlags(mask, value byte) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("tcp-flags/%#02x=%#02x", mask, value), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, 47+1)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 6, e.Next),
			// A single byte needs no byte swapping.
			asm.LoadMem(asm.R3, frame, 47, asm.Byte),
			asm.And.Imm(asm.R3, int32(mask)),
			asm.JEq.Imm(asm.R3, int32(value), e.Redirect),
		), nil
	})
}

// vniLE byte-swaps a 24-bit VXLAN VNI for comparison against a little-endian
// 32-bit load of the three VNI bytes plus the trailing reserved byte.
func vniLE(vni uint32) int32 {
	return int32((vni&0xff)<<16 | (vni & 0xff00) | (vni>>16)&0xff)
}

// matchVXLAN matches VXLAN (UDP/4789) carrying a specific VNI — three
// conditions ANDed inside one block, which WithFilter's OR cannot express.
func matchVXLAN(vni uint32) afxdp.Match {
	return afxdp.NewMatch(fmt.Sprintf("vxlan/%d", vni), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, 46+4)...)
		return append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, 23, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next),
			asm.LoadMem(asm.R3, frame, 36, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(4789), e.Next),
			// Eth 14 + IPv4 20 + UDP 8 = 42 starts the VXLAN header; the VNI
			// is the 3 bytes at +4. Load 4 and mask the reserved byte off.
			asm.LoadMem(asm.R3, frame, 46, asm.Word),
			asm.And.Imm(asm.R3, 0x00ffffff),
			asm.JEq.Imm(asm.R3, vniLE(vni), e.Redirect),
		), nil
	})
}

// matchDstMAC matches a destination MAC, read from the raw frame start because
// the MAC precedes any VLAN tag.
func matchDstMAC(s string) afxdp.Match {
	mac, err := net.ParseMAC(s)
	if err != nil {
		return afxdp.MatchError("dst-mac(invalid)", err)
	}
	if len(mac) != 6 {
		return afxdp.MatchError("dst-mac(invalid)",
			fmt.Errorf("need a 6-byte Ethernet address, got %d bytes from %q", len(mac), s))
	}
	lo := uint32(mac[0]) | uint32(mac[1])<<8 | uint32(mac[2])<<16 | uint32(mac[3])<<24
	hi := uint32(mac[4]) | uint32(mac[5])<<8
	return afxdp.NewMatch("dst-mac/"+mac.String(), func(e afxdp.MatchEnv) (asm.Instructions, error) {
		ins := e.Bounds(e.Data, 6)
		return append(ins,
			// Six bytes needs two compares: a 32-bit one then a 16-bit one.
			asm.LoadMem(asm.R3, e.Data, 0, asm.Word),
			asm.JNE.Imm32(asm.R3, int32(lo), e.Next),
			asm.LoadMem(asm.R3, e.Data, 4, asm.Half),
			asm.JEq.Imm(asm.R3, int32(hi), e.Redirect),
		), nil
	})
}

// --- packet construction -----------------------------------------------------

type frameOpts struct {
	etherType uint16 // 0 = derive from v6
	vlan      uint16 // 0 = untagged (inner/C-tag)
	vlan2     uint16 // 0 = none; outer S-tag, making the frame QinQ
	ipOpts    int    // bytes of IPv4 options (multiple of 4), for IHL > 5
	dstMAC    net.HardwareAddr
	v6        bool
	proto     uint8 // IP protocol
	sport     uint16
	dport     uint16
	tcpFlags  byte
	srcIP     string // default 10.0.0.1 / 2001:db8::1
	dstIP     string // default 10.0.0.2 / 2001:db8::2
	vni       uint32
	withVNI   bool // append a VXLAN header after UDP
}

// buildFrame assembles an Ethernet(+VLAN)/IP/L4 frame. When the EtherType is
// neither IPv4 nor IPv6 only the Ethernet header and a payload are emitted.
func ip4or(s, def string) []byte {
	if s == "" {
		s = def
	}
	return net.ParseIP(s).To4()
}

func ip6or(s, def string) []byte {
	if s == "" {
		s = def
	}
	return net.ParseIP(s).To16()
}

func buildFrame(o frameOpts) []byte {
	dst := o.dstMAC
	if dst == nil {
		dst = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	}
	b := append([]byte{}, dst...)
	b = append(b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02) // src MAC
	if o.vlan2 != 0 {
		b = binary.BigEndian.AppendUint16(b, 0x88a8) // 802.1ad S-tag
		b = binary.BigEndian.AppendUint16(b, o.vlan2)
	}
	if o.vlan != 0 {
		b = binary.BigEndian.AppendUint16(b, 0x8100)
		b = binary.BigEndian.AppendUint16(b, o.vlan)
	}
	et := o.etherType
	if et == 0 {
		et = afxdp.EtherTypeIPv4
		if o.v6 {
			et = afxdp.EtherTypeIPv6
		}
	}
	b = binary.BigEndian.AppendUint16(b, et)

	switch et {
	case afxdp.EtherTypeIPv4:
		ip := make([]byte, 20+o.ipOpts)
		ip[0] = 0x40 | byte(5+o.ipOpts/4) // IHL grows with options
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)+8))
		ip[8] = 64 // TTL
		ip[9] = o.proto
		copy(ip[12:], ip4or(o.srcIP, "10.0.0.1"))
		copy(ip[16:], ip4or(o.dstIP, "10.0.0.2"))
		for i := 20; i < 20+o.ipOpts; i++ {
			ip[i] = 1 // NOP option
		}
		b = append(b, ip...)
	case afxdp.EtherTypeIPv6:
		ip6 := make([]byte, 40)
		ip6[0] = 0x60 // version 6
		binary.BigEndian.PutUint16(ip6[4:], 8)
		ip6[6] = o.proto // Next Header
		ip6[7] = 64      // hop limit
		copy(ip6[8:], ip6or(o.srcIP, "2001:db8::1"))
		copy(ip6[24:], ip6or(o.dstIP, "2001:db8::2"))
		b = append(b, ip6...)
	default:
		return append(b, make([]byte, 46)...)
	}

	switch o.proto {
	case 6: // TCP, 20-byte header
		t := make([]byte, 20)
		binary.BigEndian.PutUint16(t[0:], o.sport)
		binary.BigEndian.PutUint16(t[2:], o.dport)
		t[12] = 5 << 4 // data offset
		t[13] = o.tcpFlags
		b = append(b, t...)
	case 17: // UDP
		u := make([]byte, 8)
		binary.BigEndian.PutUint16(u[0:], o.sport)
		binary.BigEndian.PutUint16(u[2:], o.dport)
		binary.BigEndian.PutUint16(u[4:], 8)
		b = append(b, u...)
		if o.withVNI {
			v := make([]byte, 8)
			v[0] = 0x08 // VXLAN flags: VNI present
			v[4], v[5], v[6] = byte(o.vni>>16), byte(o.vni>>8), byte(o.vni)
			b = append(b, v...)
		}
	}
	return b
}

func udpFrame(dport uint16) []byte {
	return buildFrame(frameOpts{proto: 17, sport: 1234, dport: dport})
}
func tcpFrame(dport uint16) []byte {
	return buildFrame(frameOpts{proto: 6, sport: 1234, dport: dport})
}
func arpFrame() []byte { return buildFrame(frameOpts{etherType: afxdp.EtherTypeARP}) }
func vlanUDPFrame(v uint16) []byte {
	return buildFrame(frameOpts{vlan: 100, proto: 17, sport: 1234, dport: v})
}
func runtFrame() []byte { return make([]byte, 14) } // Ethernet header only

// bpfProbe records, once per run, whether this environment can load an XDP
// program AND execute it with BPF_PROG_TEST_RUN. Both are needed by every test
// here, and both need more than raising RLIMIT_MEMLOCK.
var (
	bpfProbeOnce sync.Once
	bpfProbeErr  error
)

// requireBPF skips the whole test when the environment cannot run the dry-run
// harness. The capability decision is made HERE, once — deliberately not inside
// the table loops. Turning a per-case BPF failure into a per-case skip would
// let the entire suite report green while testing nothing, which is the worst
// possible outcome for tests whose job is catching byte-order arithmetic that
// verifies cleanly and matches the wrong traffic. Past this point, any error
// from DryRun is a real failure.
func requireBPF(t *testing.T) {
	t.Helper()
	bpfProbeOnce.Do(func() {
		if err := rlimit.RemoveMemlock(); err != nil {
			bpfProbeErr = fmt.Errorf("cannot raise memlock (need privileges): %w", err)
			return
		}
		// Canary: a plain built-in filter over a minimal frame, chosen to be
		// independent of the code under test.
		if _, err := afxdp.MatchPacket(make([]byte, 14), afxdp.WithFilter(afxdp.MatchUDPPort(5000))); err != nil {
			bpfProbeErr = fmt.Errorf("cannot load and test-run BPF programs here: %w", err)
		}
	})
	if bpfProbeErr != nil {
		t.Skipf("skipping: %v", bpfProbeErr)
	}
}

// mustDryRun runs pkt through matches and fails the test on any error, printing
// the verifier listing when there is one (%v alone truncates it to one line).
//
// Everything goes through the public MatchPacket, so these cases exercise the
// API users actually call, exceptions included.
func mustDryRun(t *testing.T, exceptions, matches []afxdp.Match, pkt []byte) bool {
	t.Helper()
	var (
		got bool
		err error
	)
	opts := []afxdp.Option{afxdp.WithFilter(matches...)}
	if len(exceptions) > 0 {
		opts = append(opts, afxdp.WithExcept(exceptions...))
	}
	got, err = afxdp.MatchPacket(pkt, opts...)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected the filter:\n%+v", ve)
		}
		t.Fatalf("DryRun: %v", err)
	}
	return got
}

// TestCustomMatch is the behavioral proof: a Match built entirely from the
// exported API classifies the packets it should and, just as importantly, does
// not classify the near misses.
func TestCustomMatch(t *testing.T) {
	requireBPF(t)

	udp5000 := matchUDPDstPort(5000)
	tcp443 := matchTCPDstPortViaLabel(443)

	cases := []struct {
		name       string
		matches    []afxdp.Match
		exceptions []afxdp.Match
		pkt        []byte
		want       bool
	}{
		{"udp-5000-hit", []afxdp.Match{udp5000}, nil, udpFrame(5000), true},
		{"udp-5001-miss", []afxdp.Match{udp5000}, nil, udpFrame(5001), false},
		{"tcp-5000-miss", []afxdp.Match{udp5000}, nil, tcpFrame(5000), false},
		{"arp-miss", []afxdp.Match{udp5000}, nil, arpFrame(), false},
		// FrameBase must skip a single 802.1Q tag, so the same rule matches a
		// tagged frame. Today this promise is asserted only by a comment.
		{"vlan-tagged-hit", []afxdp.Match{udp5000}, nil, vlanUDPFrame(5000), true},
		{"vlan-tagged-miss", []afxdp.Match{udp5000}, nil, vlanUDPFrame(5001), false},
		// Bounds must reject a runt without matching or crashing. 14 bytes is
		// the shortest input BPF_PROG_TEST_RUN accepts for XDP.
		{"runt-pass", []afxdp.Match{udp5000}, nil, runtFrame(), false},
		// Label-based control flow, and the TCP path of the second matcher.
		{"tcp-443-hit", []afxdp.Match{tcp443}, nil, tcpFrame(443), true},
		{"tcp-444-miss", []afxdp.Match{tcp443}, nil, tcpFrame(444), false},
		{"udp-443-miss", []afxdp.Match{tcp443}, nil, udpFrame(443), false},
		// Two different custom matches in one program: the case collision-free
		// labels exist to prevent. Both legs must still work, and OR holds.
		{"two-custom-udp", []afxdp.Match{udp5000, tcp443}, nil, udpFrame(5000), true},
		{"two-custom-tcp", []afxdp.Match{udp5000, tcp443}, nil, tcpFrame(443), true},
		{"two-custom-neither", []afxdp.Match{udp5000, tcp443}, nil, udpFrame(9999), false},
		// Custom composed with a built-in: OR semantics across the boundary.
		{"mixed-custom-hit", []afxdp.Match{udp5000, afxdp.MatchICMPv4Echo()}, nil, udpFrame(5000), true},
		{"mixed-builtin-hit", []afxdp.Match{udp5000, afxdp.MatchTCPPort(443)}, nil, tcpFrame(443), true},
		{"mixed-neither", []afxdp.Match{udp5000, afxdp.MatchTCPPort(443)}, nil, tcpFrame(444), false},
		// A custom match used as an exception: exceptions win and pass.
		{"custom-exception-wins", []afxdp.Match{afxdp.MatchAll()}, []afxdp.Match{udp5000}, udpFrame(5000), false},
		{"custom-exception-other", []afxdp.Match{afxdp.MatchAll()}, []afxdp.Match{udp5000}, udpFrame(5001), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustDryRun(t, tc.exceptions, tc.matches, tc.pkt); got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCustomMatchExamples verifies the matchers shipped in
// examples/customfilter. Every case pairs a hit with a near miss, because the
// failure mode that matters here is a byte-order slip that still verifies and
// still matches *something*.
func TestCustomMatchExamples(t *testing.T) {
	requireBPF(t)

	myMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x11, 0xee, 0xff}
	otherMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x11, 0xee, 0x01}
	// mac[3] >= 0x80 puts the high bit in the 32-bit immediate.
	highMAC := net.HardwareAddr{0x01, 0x02, 0x03, 0xf0, 0x05, 0x06}
	bcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	cases := []struct {
		name  string
		match afxdp.Match
		pkt   []byte
		want  bool
	}{
		// VLAN ID: read from the raw frame start, since FrameBase skips the tag.
		{"vlan-hit", matchVLAN(100), vlanUDPFrame(53), true},
		{"vlan-wrong-id", matchVLAN(101), vlanUDPFrame(53), false},
		{"vlan-untagged", matchVLAN(100), udpFrame(53), false},
		// A VID above 255 exercises both bytes of the swapped compare.
		{"vlan-high-id-hit", matchVLAN(4000), buildFrame(frameOpts{vlan: 4000, proto: 17, dport: 53}), true},
		{"vlan-high-id-miss", matchVLAN(4000), buildFrame(frameOpts{vlan: 4001, proto: 17, dport: 53}), false},

		// Source port, and the near miss that proves it is not reading dport.
		{"udp-src-hit", matchUDPSrcPort(53), buildFrame(frameOpts{proto: 17, sport: 53, dport: 9999}), true},
		{"udp-src-is-not-dst", matchUDPSrcPort(53), buildFrame(frameOpts{proto: 17, sport: 9999, dport: 53}), false},

		// TCP flags, the "connection opener" rule: SYN set, ACK clear.
		{"tcp-syn-hit", matchTCPFlags(tcpSYN|tcpACK, tcpSYN), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpSYN}), true},
		{"tcp-synack-miss", matchTCPFlags(tcpSYN|tcpACK, tcpSYN), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpSYN | tcpACK}), false},
		{"tcp-fin-miss", matchTCPFlags(tcpSYN|tcpACK, tcpSYN), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpFIN}), false},
		{"tcp-syn-not-udp", matchTCPFlags(tcpSYN|tcpACK, tcpSYN), udpFrame(443), false},
		// The second rule the tcpsyn example installs with -synack, which
		// must accept exactly the replies the first one rejects.
		{"tcp-synack-rule-hit", matchTCPFlags(tcpSYN|tcpACK, tcpSYN|tcpACK), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpSYN | tcpACK}), true},
		{"tcp-synack-rule-miss-syn", matchTCPFlags(tcpSYN|tcpACK, tcpSYN|tcpACK), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpSYN}), false},
		// A packet with other flags set alongside SYN still matches: the mask
		// is what makes this different from an equality compare.
		{"tcp-syn-with-other-flags", matchTCPFlags(tcpSYN|tcpACK, tcpSYN), buildFrame(frameOpts{proto: 6, dport: 443, tcpFlags: tcpSYN | 0x08}), true},

		// VXLAN: all three conditions must hold, and each must be able to fail.
		{"vxlan-hit", matchVXLAN(1234), buildFrame(frameOpts{proto: 17, dport: 4789, withVNI: true, vni: 1234}), true},
		{"vxlan-wrong-vni", matchVXLAN(1234), buildFrame(frameOpts{proto: 17, dport: 4789, withVNI: true, vni: 1235}), false},
		{"vxlan-wrong-port", matchVXLAN(1234), buildFrame(frameOpts{proto: 17, dport: 4790, withVNI: true, vni: 1234}), false},
		// A VNI using all three bytes catches a partial byte swap.
		{"vxlan-wide-vni-hit", matchVXLAN(0xABCDEF), buildFrame(frameOpts{proto: 17, dport: 4789, withVNI: true, vni: 0xABCDEF}), true},
		{"vxlan-wide-vni-miss", matchVXLAN(0xABCDEF), buildFrame(frameOpts{proto: 17, dport: 4789, withVNI: true, vni: 0xEFCDAB}), false},

		// Destination MAC, including on a tagged frame: the MAC precedes the
		// tag, so reading from e.Data is what makes this work.
		{"dst-mac-hit", matchDstMAC(myMAC.String()), buildFrame(frameOpts{dstMAC: myMAC, proto: 17, dport: 53}), true},
		{"dst-mac-miss", matchDstMAC(myMAC.String()), buildFrame(frameOpts{dstMAC: otherMAC, proto: 17, dport: 53}), false},
		{"dst-mac-tagged-hit", matchDstMAC(myMAC.String()), buildFrame(frameOpts{dstMAC: myMAC, vlan: 100, proto: 17, dport: 53}), true},
		// The first four MAC bytes are compared as one 32-bit immediate. With
		// mac[3] >= 0x80 that value has its high bit set, which is why the
		// matcher uses JNE.Imm32 (a 32-bit compare) and not JNE.Imm: a 64-bit
		// compare against a sign-extended negative would never be equal, and
		// the matcher would silently never fire.
		{"dst-mac-high-bit-hit", matchDstMAC(highMAC.String()), buildFrame(frameOpts{dstMAC: highMAC, proto: 17, dport: 53}), true},
		{"dst-mac-high-bit-miss", matchDstMAC(highMAC.String()), buildFrame(frameOpts{dstMAC: myMAC, proto: 17, dport: 53}), false},
		{"dst-mac-broadcast-hit", matchDstMAC(bcastMAC.String()), buildFrame(frameOpts{dstMAC: bcastMAC, proto: 17, dport: 53}), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustDryRun(t, nil, []afxdp.Match{tc.match}, tc.pkt); got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCustomMatchFallThrough pins the NewMatch contract that a block which
// never jumps to Redirect is treated as "no match" rather than depending on
// the physical adjacency of the blocks around it.
func TestCustomMatchFallThrough(t *testing.T) {
	requireBPF(t)

	// Emits no jumps at all: pure fall-through, which must mean "no match".
	never := afxdp.NewMatch("custom-never", func(afxdp.MatchEnv) (asm.Instructions, error) {
		return asm.Instructions{asm.Mov.Imm(asm.R3, 0)}, nil
	})
	// Placed before a match that would otherwise fire, to prove the
	// fall-through lands on the next rule and not somewhere else.
	matches := []afxdp.Match{never, matchUDPDstPort(5000)}
	if !mustDryRun(t, nil, matches, udpFrame(5000)) {
		t.Error("fall-through custom match swallowed the packet; want the next rule to match")
	}
	if mustDryRun(t, nil, matches, udpFrame(5001)) {
		t.Error("redirect = true, want false")
	}

	// An empty block is the degenerate case of the same contract.
	empty := afxdp.NewMatch("custom-empty", func(afxdp.MatchEnv) (asm.Instructions, error) { return nil, nil })
	if mustDryRun(t, nil, []afxdp.Match{empty, matchUDPDstPort(5000)}, udpFrame(5001)) {
		t.Error("empty custom match redirected; want no match")
	}
}

// TestCustomMatchRequiresBounds pins the safety property behind MatchEnv.Bounds:
// a custom match that loads from the packet without bounds-checking first is
// rejected by the verifier, so the mistake surfaces as an error from Open
// rather than as a bad read at line rate.
func TestCustomMatchRequiresBounds(t *testing.T) {
	requireBPF(t)

	_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(matchUnbounded()))
	if err == nil {
		t.Fatal("unbounded packet load was accepted; want a verifier rejection")
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		t.Fatalf("want an *ebpf.VerifierError, got %T: %v", err, err)
	}
}

// TestInvalidMatchesError checks that malformed Match values produce errors
// rather than panicking somewhere inside Open. Users construct Matches now, so
// a nil build func and a zero-value Match are both reachable by accident.
func TestInvalidMatchesError(t *testing.T) {
	requireBPF(t)

	cases := []struct {
		name  string
		match afxdp.Match
		want  string // substring the error must contain
	}{
		{"nil-build", afxdp.NewMatch("custom-nil", nil), "nil build func"},
		{"zero-value", afxdp.Match{}, "no build func"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The panic this replaced would have failed the test anyway; the
			// point is that the error is clean and says what to do.
			_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(tc.match))
			if err == nil {
				t.Fatal("no error for an invalid match")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestCustomMatchReservedRegister checks that a block touching R8 is rejected.
// R8 carries rx_queue_index for the redirect tail; a block that clobbers it
// loads, verifies, attaches and then delivers packets to the wrong queue's
// socket with no error anywhere. That silence is why this is enforced rather
// than merely documented.
func TestCustomMatchReservedRegister(t *testing.T) {
	requireBPF(t)

	cases := map[string]afxdp.Match{
		// The realistic mistake: R8 picked as a scratch register for a load.
		"write-via-load": afxdp.NewMatch("clobber-load", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			ins, frame := e.FrameBase()
			ins = append(ins, e.Bounds(frame, afxdp.OffEtherType+2)...)
			return append(ins,
				asm.LoadMem(asm.R8, frame, afxdp.OffEtherType, asm.Half),
				asm.JEq.Imm(asm.R8, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Redirect),
			), nil
		}),
		"write-via-mov": afxdp.NewMatch("clobber-mov", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{
				asm.Mov.Imm(asm.R8, 0),
				asm.Ja.Label(e.Next),
			}, nil
		}),
		// Rejected too: the contract is "do not mention R8", which keeps the
		// check from having to model per-opcode operand semantics.
		"read-as-source": afxdp.NewMatch("read-r8", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{
				asm.Mov.Reg(asm.R3, asm.R8),
				asm.Ja.Label(e.Next),
			}, nil
		}),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
			if err == nil {
				t.Fatal("a block referencing R8 was accepted")
			}
			if !strings.Contains(err.Error(), "R8") {
				t.Errorf("error %q does not mention R8", err)
			}
		})
	}

	// R6/R7 are read-only. Writing R7 is the dangerous one: it silently
	// re-bases every later block in the filter, including the built-in
	// matchers and the WithKeepManagement exceptions, so they parse at the
	// wrong offset with no error anywhere.
	t.Run("write-frame-pointer", func(t *testing.T) {
		m := afxdp.NewMatch("move-r7", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{asm.Add.Imm(asm.R7, 4), asm.Ja.Label(e.Next)}, nil
		})
		_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
		if err == nil || !strings.Contains(err.Error(), "R7") {
			t.Fatalf("writing R7 gave %v, want a rejection naming R7", err)
		}
	})
	t.Run("write-data-end", func(t *testing.T) {
		m := afxdp.NewMatch("move-r6", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{asm.Add.Imm(asm.R6, 4), asm.Ja.Label(e.Next)}, nil
		})
		_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
		if err == nil || !strings.Contains(err.Error(), "R6") {
			t.Fatalf("writing R6 gave %v, want a rejection naming R6", err)
		}
	})
	// Reading R6/R7 must keep working — it is what MatchEnv is for, and
	// FrameBase and Bounds emit such reads themselves.
	t.Run("reading-r6-r7-still-allowed", func(t *testing.T) {
		if !mustDryRun(t, nil, []afxdp.Match{matchUDPDstPort(5000)}, udpFrame(5000)) {
			t.Error("a matcher that reads R6/R7 was rejected")
		}
	})
	// The write check is per opcode class, not per Dst field: a conditional
	// jump READS its Dst (it is the left operand of the comparison), so R6/R7
	// there is legal. This block writes nothing to either register.
	t.Run("jump-with-r6-r7-as-left-operand", func(t *testing.T) {
		m := afxdp.NewMatch("jump-reads", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{
				asm.Mov.Reg(asm.R2, e.Data),
				asm.Add.Imm(asm.R2, 14),
				// data_end as the LEFT operand: "if r6 <= r2 goto next".
				asm.JLE.Reg(asm.R6, asm.R2, e.Next),
				// data as the LEFT operand of a compare against itself + 0.
				asm.JGT.Reg(asm.R7, asm.R6, e.Next),
				asm.Ja.Label(e.Redirect),
			}, nil
		})
		if !mustDryRun(t, nil, []afxdp.Match{m}, udpFrame(5000)) {
			t.Error("a block reading R6/R7 via jump Dst operands was rejected or did not run")
		}
	})
	// Storing R6/R7's VALUE (Src operand) is a read too.
	t.Run("store-r7-value", func(t *testing.T) {
		m := afxdp.NewMatch("store-src", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{
				asm.StoreMem(asm.RFP, -8, e.Data, asm.DWord),
				asm.Ja.Label(e.Redirect),
			}, nil
		})
		if !mustDryRun(t, nil, []afxdp.Match{m}, udpFrame(5000)) {
			t.Error("a block storing R7's value was rejected or did not run")
		}
	})
	// Writes are still rejected: loads into R6/R7, ALU on them.
	for name, m := range map[string]afxdp.Match{
		"load-into-r6": afxdp.NewMatch("w6", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{asm.LoadMem(asm.R6, e.Data, 0, asm.Byte), asm.Ja.Label(e.Next)}, nil
		}),
		"alu-on-r7": afxdp.NewMatch("w7", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{asm.Add.Imm(asm.R7, 4), asm.Ja.Label(e.Next)}, nil
		}),
	} {
		t.Run("write-still-rejected/"+name, func(t *testing.T) {
			_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
			if err == nil || !strings.Contains(err.Error(), "read-only") {
				t.Fatalf("got %v, want a read-only rejection", err)
			}
		})
	}
	// And R8 stays completely forbidden, reads included — even as a jump's
	// left operand, which for R6/R7 is now allowed.
	t.Run("r8-jump-read-still-forbidden", func(t *testing.T) {
		m := afxdp.NewMatch("r8-jump", func(e afxdp.MatchEnv) (asm.Instructions, error) {
			return asm.Instructions{asm.JEq.Imm(asm.R8, 0, e.Next), asm.Ja.Label(e.Next)}, nil
		})
		_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
		if err == nil || !strings.Contains(err.Error(), "R8") {
			t.Fatalf("got %v, want an R8 rejection", err)
		}
	})
}

// TestCustomMatchCannotReturnAction checks that a block ending in an XDP
// action is rejected. Such a block loads happily, and with any exception
// present (every WithKeepManagement user has some) the filter then returns
// that action for every packet reaching the block — so a stray Return() of
// XDP_DROP silently overrides WithKeepManagement and can take the box off the
// network. Deciding the action belongs to the filter, not to a match.
func TestCustomMatchCannotReturnAction(t *testing.T) {
	requireBPF(t)

	m := afxdp.NewMatch("dropper", func(afxdp.MatchEnv) (asm.Instructions, error) {
		return asm.Instructions{asm.Mov.Imm(asm.R0, 1 /* XDP_DROP */), asm.Return()}, nil
	})
	_, err := afxdp.MatchPacket(udpFrame(5000), afxdp.WithFilter(m))
	if err == nil {
		t.Fatal("a block returning XDP_DROP was accepted")
	}
	if !strings.Contains(err.Error(), "returns an XDP action") {
		t.Errorf("error %q does not explain the problem", err)
	}
}

// TestMatchPacketParity checks that MatchPacket agrees with Open on the two
// builders whose blocks never fall through. Both used to be rejected here for
// leaving one of the harness's tails unreachable, which meant MatchPacket
// refused filters Open accepts.
func TestMatchPacketParity(t *testing.T) {
	requireBPF(t)

	if got := mustDryRun(t, nil, []afxdp.Match{afxdp.MatchAll()}, udpFrame(5000)); !got {
		t.Error("MatchAll did not match")
	}
	if got := mustDryRun(t, nil, []afxdp.Match{afxdp.MatchNone()}, udpFrame(5000)); got {
		t.Error("MatchNone matched")
	}
	// A packet shorter than an Ethernet header gets an explanation, not the
	// kernel's bare EINVAL.
	if _, err := afxdp.MatchPacket(make([]byte, 4), afxdp.WithFilter(afxdp.MatchUDPPort(53))); err == nil ||
		!strings.Contains(err.Error(), "14 bytes") {
		t.Errorf("short packet gave %v, want an explanation", err)
	}

	// The built-in matchers and a well-behaved custom one must still pass.
	if !mustDryRun(t, nil, []afxdp.Match{matchUDPDstPort(5000)}, udpFrame(5000)) {
		t.Error("the R8 check rejected a legitimate block")
	}
}

// TestMatchErrorThroughOpen checks the escape hatch a third-party matcher
// constructor needs: validate arguments, return MatchError, and have the real
// Open surface something the caller can act on.
func TestMatchErrorThroughOpen(t *testing.T) {
	requireBPF(t)

	// matchDstMAC is the shape a user would write: validate the argument,
	// report a bad one with MatchError, and let Open surface it.
	matchSrcMAC := matchDstMAC

	iface, _ := afxdp.NewVethPair(t)

	for _, tc := range []struct {
		name, mac, want string
	}{
		{"unparseable", "not-a-mac", "invalid MAC address"},
		// net.ParseMAC accepts EUI-64; the matcher only handles 6 bytes.
		{"eui-64", "aa:bb:cc:dd:ee:ff:00:11", "got 8 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fleet, err := afxdp.Open(iface, afxdp.WithFilter(matchSrcMAC(tc.mac)))
			if err == nil {
				fleet.Close()
				t.Fatal("Open accepted a match built from an invalid argument")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Open error %q does not explain the problem (want %q)", err, tc.want)
			}
		})
	}

	// And the same constructor with a valid argument opens and captures, so
	// the error path is not just rejecting everything. This is also the only
	// test that drives a custom match through the real redirect tail rather
	// than the dry-run sentinel.
	fleet, err := afxdp.Open(iface, afxdp.WithFilter(matchSrcMAC("aa:bb:cc:dd:ee:ff")))
	if err != nil {
		t.Fatalf("Open with a valid MAC: %v", err)
	}
	defer fleet.Close()
	info, err := fleet.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if !strings.Contains(info.Filter, "dst-mac/aa:bb:cc:dd:ee:ff") {
		t.Errorf("Info.Filter = %q, want it to name the custom match", info.Filter)
	}
}

// TestCustomMatchPreservesUserLabel checks that the library's entry symbol does
// not destroy a symbol the builder already put on its first instruction. Before
// this was handled, a loop label on instruction 0 — the natural use of Label —
// vanished and the program failed to load with "unsatisfied program reference"
// for a symbol the user had plainly defined.
func TestCustomMatchPreservesUserLabel(t *testing.T) {
	requireBPF(t)

	// The first instruction carries the user's own label, and a later
	// instruction jumps back to it.
	m := afxdp.NewMatch("custom-userlabel", func(e afxdp.MatchEnv) (asm.Instructions, error) {
		top := e.Label("top")
		ins, frame := e.FrameBase()
		ins = append(ins, e.Bounds(frame, offL4Dport+2)...)
		ins = append(ins,
			asm.LoadMem(asm.R3, frame, afxdp.OffEtherType, asm.Half),
			asm.JNE.Imm(asm.R3, afxdp.NetShort(afxdp.EtherTypeIPv4), e.Next),
			asm.LoadMem(asm.R3, frame, offIPProto, asm.Byte),
			asm.JNE.Imm(asm.R3, 17, e.Next),
			asm.LoadMem(asm.R3, frame, offL4Dport, asm.Half),
			asm.JEq.Imm(asm.R3, afxdp.NetShort(5000), e.Redirect),
			// A reference back to the label, which makes it load-bearing: if
			// the symbol were dropped the program would not assemble at all.
			// R4 is provably zero, so the branch is never taken and the
			// verifier does not see it as a loop.
			asm.Mov.Imm(asm.R4, 0),
			asm.JNE.Imm(asm.R4, 0, top),
		)
		ins[0] = ins[0].WithSymbol(top)
		return ins, nil
	})

	if !mustDryRun(t, nil, []afxdp.Match{m}, udpFrame(5000)) {
		t.Error("redirect = false, want true")
	}
	if mustDryRun(t, nil, []afxdp.Match{m}, udpFrame(5001)) {
		t.Error("redirect = true, want false")
	}
}

// TestCustomMatchMultiBuffer checks that a custom match loads under
// BPF_F_XDP_HAS_FRAGS as well as plain, which is what WithMultiBuffer needs.
//
// Note the frags flag does not change what the verifier accepts: a
// bounds-checked read loads either way, and an unchecked one is rejected either
// way. What frags changes is runtime — data_end then covers only the first
// fragment, so a read past the linear head silently stops matching rather than
// failing to load. That is why MatchEnv.DataEnd tells custom matches to stay
// within the L2/L3/L4 headers.
func TestCustomMatchMultiBuffer(t *testing.T) {
	requireBPF(t)

	matches := []afxdp.Match{matchUDPDstPort(5000), matchTCPDstPortViaLabel(443)}
	// Load the real filter program with the frags flag, as Open would.
	if err := afxdp.BuildFilterProgramFrags(4, nil, matches); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("custom matches rejected under xdp.frags:\n%+v", ve)
		}
		// requireBPF proved this environment loads programs; an error here is real.
		t.Fatalf("BuildFilterProgramFrags: %v", err)
	}
	// And through the public path: WithMultiBuffer makes MatchPacket set
	// BPF_F_XDP_HAS_FRAGS on the test program too.
	if got := func() bool {
		ok, err := afxdp.MatchPacket(udpFrame(5000),
			afxdp.WithFilter(matches...), afxdp.WithMultiBuffer())
		if err != nil {
			t.Fatalf("MatchPacket with WithMultiBuffer: %v", err)
		}
		return ok
	}(); !got {
		t.Error("udp/5000 did not match under the frags-flagged program")
	}
}

// --- restored behavioral tests for the Part 2 built-ins --------------------

// advIPv4Options builds an IPv4 packet with IHL=6 whose four option bytes are
// chosen so the bytes at the FIXED L4 offsets (34/36) — which with options are
// inside the IP header, not the transport header — spell the target port.
func advIPv4Options(proto uint8, fakePortAt36 uint16) []byte {
	b := []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00}
	ip := make([]byte, 24) // IHL=6
	ip[0] = 0x46
	binary.BigEndian.PutUint16(ip[2:], 24+8)
	ip[8], ip[9] = 64, proto
	copy(ip[12:], net.ParseIP("192.0.2.1").To4())
	copy(ip[16:], net.ParseIP("192.0.2.2").To4())
	binary.BigEndian.PutUint16(ip[22:], fakePortAt36) // option bytes = frame[36:38]
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[2:], 9999) // the REAL destination port
	return append(append(b, ip...), l4...)
}

// advIPv4Fragment builds a NON-FIRST IPv4 fragment whose payload bytes at the
// fixed L4 offsets spell the target port or ICMP type. A non-first fragment
// has no transport header at all — those bytes are mid-datagram payload.
func advIPv4Fragment(proto uint8, payloadAt34 [4]byte) []byte {
	b := []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00}
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	binary.BigEndian.PutUint16(ip[6:], 1480/8) // fragment offset 185
	ip[8], ip[9] = 64, proto
	copy(ip[12:], net.ParseIP("192.0.2.1").To4())
	copy(ip[16:], net.ParseIP("192.0.2.2").To4())
	payload := make([]byte, 8)
	copy(payload, payloadAt34[:])
	return append(append(b, ip...), payload...)
}

// TestIPv4FixedOffsetGuards pins the fix for a real false-match bug: the
// fixed-offset L4 matchers used to read offsets 34/36 unconditionally, so an
// IPv4 packet with options (IHL>5) or a non-first fragment whose bytes there
// happened to spell the right port MATCHED — not merely "didn't match". The
// matchers now require IHL=5 and fragment offset 0 before any L4 read.
func TestIPv4FixedOffsetGuards(t *testing.T) {
	requireBPF(t)

	for _, tc := range []struct {
		name  string
		match afxdp.Match
		pkt   []byte
		want  bool
	}{
		// The adversarial packets: all four used to return true.
		{"options-fake-udp-port", afxdp.MatchUDPPort(53), advIPv4Options(17, 53), false},
		{"options-fake-tcp-port", afxdp.MatchTCPPort(443), advIPv4Options(6, 443), false},
		{"fragment-fake-udp-port", afxdp.MatchUDPPort(53), advIPv4Fragment(17, [4]byte{0, 53, 0, 53}), false},
		{"fragment-fake-icmp-echo", afxdp.MatchICMPv4Echo(), advIPv4Fragment(1, [4]byte{8, 0, 0, 0}), false},
		// Source ports go through the same code path.
		{"fragment-fake-udp-src", afxdp.MatchUDPSrcPort(53), advIPv4Fragment(17, [4]byte{0, 53, 0, 53}), false},
		// A FIRST fragment (offset 0, MF set) carries the real L4 header and
		// must still match — the guard is on the offset, not the MF bit.
		{"first-fragment-matches", afxdp.MatchUDPPort(53), func() []byte {
			f := udpFrame(53)
			binary.BigEndian.PutUint16(f[20:], 0x2000) // MF set, offset 0
			return f
		}(), true},
		// Plain packets keep matching, and IPv6 is untouched by the guard.
		{"plain-still-matches", afxdp.MatchUDPPort(53), udpFrame(53), true},
		{"v6-still-matches", afxdp.MatchUDPPort(53), buildFrame(frameOpts{v6: true, proto: 17, sport: 1, dport: 53}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustDryRun(t, nil, []afxdp.Match{tc.match}, tc.pkt); got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDualFamilyPorts pins the intentional behavior change: the port builders
// match IPv4 *and* IPv6. They were silently IPv4-only, so a dual-stack user
// lost half their traffic with no error.
func TestDualFamilyPorts(t *testing.T) {
	requireBPF(t)

	v4 := func(proto uint8, sp, dp uint16) []byte {
		return buildFrame(frameOpts{proto: proto, sport: sp, dport: dp, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})
	}
	v6 := func(proto uint8, sp, dp uint16) []byte {
		return buildFrame(frameOpts{v6: true, proto: proto, sport: sp, dport: dp, srcIP: "2001:db8::1", dstIP: "2001:db8::2"})
	}
	for _, tc := range []struct {
		name  string
		match afxdp.Match
		pkt   []byte
		want  bool
	}{
		{"udp-dst v4", afxdp.MatchUDPPort(4789), v4(17, 1234, 4789), true},
		{"udp-dst v6", afxdp.MatchUDPPort(4789), v6(17, 1234, 4789), true},
		{"udp-dst v4 wrong port", afxdp.MatchUDPPort(4789), v4(17, 1234, 4790), false},
		{"udp-dst v6 wrong port", afxdp.MatchUDPPort(4789), v6(17, 1234, 4790), false},
		{"udp-dst not src", afxdp.MatchUDPPort(4789), v4(17, 4789, 1234), false},
		{"udp-dst not tcp", afxdp.MatchUDPPort(4789), v4(6, 1234, 4789), false},
		{"tcp-dst v4", afxdp.MatchTCPPort(443), v4(6, 1234, 443), true},
		{"tcp-dst v6", afxdp.MatchTCPPort(443), v6(6, 1234, 443), true},
		{"udp-src v4", afxdp.MatchUDPSrcPort(53), v4(17, 53, 4000), true},
		{"udp-src v6", afxdp.MatchUDPSrcPort(53), v6(17, 53, 4000), true},
		{"udp-src not dst", afxdp.MatchUDPSrcPort(53), v4(17, 4000, 53), false},
		{"tcp-src v4", afxdp.MatchTCPSrcPort(443), v4(6, 443, 1234), true},
		{"tcp-src v6", afxdp.MatchTCPSrcPort(443), v6(6, 443, 1234), true},
		{"udp any v4", afxdp.MatchUDPPort(), v4(17, 1, 9999), true},
		{"udp any v6", afxdp.MatchUDPPort(), v6(17, 1, 9999), true},
		{"udp any not tcp", afxdp.MatchUDPPort(), v4(6, 1, 9999), false},
		{"tagged v4", afxdp.MatchUDPPort(4789), buildFrame(frameOpts{vlan: 100, proto: 17, sport: 1, dport: 4789}), true},
		{"tagged v6", afxdp.MatchUDPPort(4789), buildFrame(frameOpts{vlan: 100, v6: true, proto: 17, sport: 1, dport: 4789}), true},
		{"runt", afxdp.MatchUDPPort(4789), make([]byte, 14), false},
		{"arp", afxdp.MatchUDPPort(4789), buildFrame(frameOpts{etherType: afxdp.EtherTypeARP}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustDryRun(t, nil, []afxdp.Match{tc.match}, tc.pkt); got != tc.want {
				t.Errorf("redirect = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWithExceptSemantics checks that user-supplied exceptions are evaluated
// first and win.
func TestWithExceptSemantics(t *testing.T) {
	requireBPF(t)

	all := []afxdp.Match{afxdp.MatchUDPPort()}      // capture all UDP...
	except := []afxdp.Match{afxdp.MatchUDPPort(53)} // ...except DNS
	if mustDryRun(t, except, all, udpFrame(53)) {
		t.Error("excepted packet was redirected")
	}
	if !mustDryRun(t, except, all, udpFrame(4789)) {
		t.Error("non-excepted packet was not redirected")
	}
	// The degenerate catch-all exception is reported plainly.
	_, err := afxdp.MatchPacket(udpFrame(53),
		afxdp.WithFilter(afxdp.MatchUDPPort(53)), afxdp.WithExcept(afxdp.MatchAll()))
	if err == nil || !strings.Contains(err.Error(), "matches every packet") {
		t.Errorf("catch-all exception gave %v, want an explanation", err)
	}
}
