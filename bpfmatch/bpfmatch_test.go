//go:build linux

package bpfmatch_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/atoonk/go-afxdp"
	"github.com/atoonk/go-afxdp/bpfmatch"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/bpf"
)

// bpfCorpus holds cBPF programs compiled by libpcap (tcpdump -ddd) and
// committed verbatim, so this test needs neither libpcap nor the tcpdump
// binary. Regenerate with:
//
//	tcpdump -ddd '<expression>'
//
// Documentation addresses only: RFC 5737 (192.0.2.0/24, 198.51.100.0/24) and
// RFC 3849 (2001:db8::/32).
var bpfCorpus = []struct {
	expr string
	raw  []bpf.RawInstruction
}{
	{"tcp port 22", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 6, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 15, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 12, Jf: 0, K: 22},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 10, Jf: 11, K: 22},
		{Op: 21, Jt: 0, Jf: 10, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 8, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 6, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 2, Jf: 0, K: 22},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 1, K: 22},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"tcp dst port 443", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 4, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 11, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 8, Jf: 9, K: 443},
		{Op: 21, Jt: 0, Jf: 8, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 6, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 4, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 1, K: 443},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"udp src port 53", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 4, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 11, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 8, Jf: 9, K: 53},
		{Op: 21, Jt: 0, Jf: 8, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 6, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 4, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 0, Jf: 1, K: 53},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"host 192.0.2.1", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 4, K: 2048},
		{Op: 32, Jt: 0, Jf: 0, K: 26},
		{Op: 21, Jt: 8, Jf: 0, K: 3221225985},
		{Op: 32, Jt: 0, Jf: 0, K: 30},
		{Op: 21, Jt: 6, Jf: 7, K: 3221225985},
		{Op: 21, Jt: 1, Jf: 0, K: 2054},
		{Op: 21, Jt: 0, Jf: 5, K: 32821},
		{Op: 32, Jt: 0, Jf: 0, K: 28},
		{Op: 21, Jt: 2, Jf: 0, K: 3221225985},
		{Op: 32, Jt: 0, Jf: 0, K: 38},
		{Op: 21, Jt: 0, Jf: 1, K: 3221225985},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"net 198.51.100.0/24", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 6, K: 2048},
		{Op: 32, Jt: 0, Jf: 0, K: 26},
		{Op: 84, Jt: 0, Jf: 0, K: 4294967040},
		{Op: 21, Jt: 11, Jf: 0, K: 3325256704},
		{Op: 32, Jt: 0, Jf: 0, K: 30},
		{Op: 84, Jt: 0, Jf: 0, K: 4294967040},
		{Op: 21, Jt: 8, Jf: 9, K: 3325256704},
		{Op: 21, Jt: 1, Jf: 0, K: 2054},
		{Op: 21, Jt: 0, Jf: 7, K: 32821},
		{Op: 32, Jt: 0, Jf: 0, K: 28},
		{Op: 84, Jt: 0, Jf: 0, K: 4294967040},
		{Op: 21, Jt: 3, Jf: 0, K: 3325256704},
		{Op: 32, Jt: 0, Jf: 0, K: 38},
		{Op: 84, Jt: 0, Jf: 0, K: 4294967040},
		{Op: 21, Jt: 0, Jf: 1, K: 3325256704},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"tcp port 22 and not src host 192.0.2.1", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 6, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 17, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 14, Jf: 0, K: 22},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 12, Jf: 13, K: 22},
		{Op: 21, Jt: 0, Jf: 12, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 10, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 8, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 2, Jf: 0, K: 22},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 3, K: 22},
		{Op: 32, Jt: 0, Jf: 0, K: 26},
		{Op: 21, Jt: 1, Jf: 0, K: 3221225985},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"udp port 53 or tcp port 80", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 11, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 4, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 25, Jf: 0, K: 53},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 23, Jf: 24, K: 53},
		{Op: 21, Jt: 0, Jf: 23, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 20, Jf: 0, K: 80},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 18, Jf: 19, K: 80},
		{Op: 21, Jt: 0, Jf: 18, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 7, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 14, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 10, Jf: 0, K: 53},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 8, Jf: 9, K: 53},
		{Op: 21, Jt: 0, Jf: 8, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 6, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 2, Jf: 0, K: 80},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 1, K: 80},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"vlan 100 and tcp port 22", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 2, Jf: 0, K: 33024},
		{Op: 21, Jt: 1, Jf: 0, K: 34984},
		{Op: 21, Jt: 0, Jf: 22, K: 37120},
		{Op: 40, Jt: 0, Jf: 0, K: 14},
		{Op: 84, Jt: 0, Jf: 0, K: 4095},
		{Op: 21, Jt: 0, Jf: 19, K: 100},
		{Op: 40, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 6, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 24},
		{Op: 21, Jt: 0, Jf: 15, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 58},
		{Op: 21, Jt: 12, Jf: 0, K: 22},
		{Op: 40, Jt: 0, Jf: 0, K: 60},
		{Op: 21, Jt: 10, Jf: 11, K: 22},
		{Op: 21, Jt: 0, Jf: 10, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 27},
		{Op: 21, Jt: 0, Jf: 8, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 24},
		{Op: 69, Jt: 6, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 18},
		{Op: 72, Jt: 0, Jf: 0, K: 18},
		{Op: 21, Jt: 2, Jf: 0, K: 22},
		{Op: 72, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 1, K: 22},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"vlan 100 and vlan 200", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 2, Jf: 0, K: 33024},
		{Op: 21, Jt: 1, Jf: 0, K: 34984},
		{Op: 21, Jt: 0, Jf: 11, K: 37120},
		{Op: 40, Jt: 0, Jf: 0, K: 14},
		{Op: 84, Jt: 0, Jf: 0, K: 4095},
		{Op: 21, Jt: 0, Jf: 8, K: 100},
		{Op: 40, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 2, Jf: 0, K: 33024},
		{Op: 21, Jt: 1, Jf: 0, K: 34984},
		{Op: 21, Jt: 0, Jf: 4, K: 37120},
		{Op: 40, Jt: 0, Jf: 0, K: 18},
		{Op: 84, Jt: 0, Jf: 0, K: 4095},
		{Op: 21, Jt: 0, Jf: 1, K: 200},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"ip6 and tcp port 443", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 7, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 5, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 21, Jt: 2, Jf: 0, K: 443},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 21, Jt: 0, Jf: 1, K: 443},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"icmp", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 3, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 1, K: 1},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"arp", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 1, K: 2054},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"tcp port 22 and tcp[tcpflags] & tcp-syn != 0", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 13, Jf: 0, K: 34525},
		{Op: 21, Jt: 0, Jf: 12, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 10, K: 6},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 8, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 2, Jf: 0, K: 22},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 3, K: 22},
		{Op: 80, Jt: 0, Jf: 0, K: 27},
		{Op: 69, Jt: 0, Jf: 1, K: 2},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"udp portrange 5000-5010", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 0, Jf: 7, K: 34525},
		{Op: 48, Jt: 0, Jf: 0, K: 20},
		{Op: 21, Jt: 0, Jf: 18, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 54},
		{Op: 53, Jt: 0, Jf: 1, K: 5000},
		{Op: 37, Jt: 0, Jf: 14, K: 5010},
		{Op: 40, Jt: 0, Jf: 0, K: 56},
		{Op: 53, Jt: 11, Jf: 13, K: 5000},
		{Op: 21, Jt: 0, Jf: 12, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 10, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 8, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 53, Jt: 0, Jf: 1, K: 5000},
		{Op: 37, Jt: 0, Jf: 3, K: 5010},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 53, Jt: 0, Jf: 2, K: 5000},
		{Op: 37, Jt: 1, Jf: 0, K: 5010},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"ether dst 02:00:00:00:00:01", []bpf.RawInstruction{
		{Op: 32, Jt: 0, Jf: 0, K: 2},
		{Op: 21, Jt: 0, Jf: 3, K: 1},
		{Op: 40, Jt: 0, Jf: 0, K: 0},
		{Op: 21, Jt: 0, Jf: 1, K: 512},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
	{"udp port 4789 and udp[12:4] & 0xffffff00 = 0x0004d200", []bpf.RawInstruction{
		{Op: 40, Jt: 0, Jf: 0, K: 12},
		{Op: 21, Jt: 14, Jf: 0, K: 34525},
		{Op: 21, Jt: 0, Jf: 13, K: 2048},
		{Op: 48, Jt: 0, Jf: 0, K: 23},
		{Op: 21, Jt: 0, Jf: 11, K: 17},
		{Op: 40, Jt: 0, Jf: 0, K: 20},
		{Op: 69, Jt: 9, Jf: 0, K: 8191},
		{Op: 177, Jt: 0, Jf: 0, K: 14},
		{Op: 72, Jt: 0, Jf: 0, K: 14},
		{Op: 21, Jt: 2, Jf: 0, K: 4789},
		{Op: 72, Jt: 0, Jf: 0, K: 16},
		{Op: 21, Jt: 0, Jf: 4, K: 4789},
		{Op: 64, Jt: 0, Jf: 0, K: 26},
		{Op: 84, Jt: 0, Jf: 0, K: 4294967040},
		{Op: 21, Jt: 0, Jf: 1, K: 315904},
		{Op: 6, Jt: 0, Jf: 0, K: 262144},
		{Op: 6, Jt: 0, Jf: 0, K: 0},
	}},
}

// cbpf disassembles a corpus entry into the instruction form Match takes.
func cbpf(t *testing.T, raw []bpf.RawInstruction) []bpf.Instruction {
	t.Helper()
	ins := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		ins[i] = r.Disassemble()
	}
	return ins
}

// bpfPackets is the packet matrix every corpus filter is evaluated against.
// It deliberately includes the cases our hand-written matchers get wrong or
// cannot see: IPv4 with options, QinQ, and IPv6.
func bpfPackets() []struct {
	name string
	pkt  []byte
} {
	type p = struct {
		name string
		pkt  []byte
	}
	return []p{
		{"v4 tcp/22 from .1", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v4 tcp/22 from .9", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, srcIP: "192.0.2.9", dstIP: "192.0.2.2"})},
		{"v4 tcp/22 src port", buildFrame(frameOpts{proto: 6, sport: 22, dport: 1234, srcIP: "192.0.2.9", dstIP: "192.0.2.2"})},
		{"v4 tcp/443", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 443, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v4 tcp/80", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 80, srcIP: "198.51.100.7", dstIP: "192.0.2.2"})},
		{"v4 tcp/22 SYN", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, tcpFlags: tcpSYN, srcIP: "192.0.2.5", dstIP: "192.0.2.2"})},
		{"v4 tcp/22 SYN+ACK", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, tcpFlags: tcpSYN | tcpACK, srcIP: "192.0.2.5", dstIP: "192.0.2.2"})},
		{"v4 udp/53 src", buildFrame(frameOpts{proto: 17, sport: 53, dport: 4000, srcIP: "198.51.100.7", dstIP: "192.0.2.2"})},
		{"v4 udp/53 dst", buildFrame(frameOpts{proto: 17, sport: 4000, dport: 53, srcIP: "198.51.100.7", dstIP: "192.0.2.2"})},
		{"v4 udp/5005", buildFrame(frameOpts{proto: 17, sport: 1, dport: 5005, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v4 udp/6000", buildFrame(frameOpts{proto: 17, sport: 1, dport: 6000, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v4 icmp", buildFrame(frameOpts{proto: 1, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"net 198.51.100", buildFrame(frameOpts{proto: 6, sport: 1, dport: 9, srcIP: "198.51.100.42", dstIP: "192.0.2.2"})},
		// IPv4 options: IHL 6 and 7. Only cBPF handles these.
		{"v4+opts(4) tcp/22", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, ipOpts: 4, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v4+opts(8) tcp/443", buildFrame(frameOpts{proto: 6, sport: 1234, dport: 443, ipOpts: 8, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"vlan100 tcp/22", buildFrame(frameOpts{vlan: 100, proto: 6, sport: 1234, dport: 22, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"vlan200 tcp/22", buildFrame(frameOpts{vlan: 200, proto: 6, sport: 1234, dport: 22, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"qinq 200/100 tcp/22", buildFrame(frameOpts{vlan: 100, vlan2: 200, proto: 6, sport: 1, dport: 22, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"v6 tcp/443", buildFrame(frameOpts{v6: true, proto: 6, sport: 1234, dport: 443, srcIP: "2001:db8::1", dstIP: "2001:db8::2"})},
		{"v6 tcp/22", buildFrame(frameOpts{v6: true, proto: 6, sport: 1234, dport: 22, srcIP: "2001:db8::1", dstIP: "2001:db8::2"})},
		{"v6 udp/53", buildFrame(frameOpts{v6: true, proto: 17, sport: 53, dport: 4000, srcIP: "2001:db8::1", dstIP: "2001:db8::2"})},
		{"arp", buildFrame(frameOpts{etherType: afxdp.EtherTypeARP})},
		{"vxlan vni 1234", buildFrame(frameOpts{proto: 17, sport: 5000, dport: 4789, withVNI: true, vni: 1234, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"vxlan vni 9999", buildFrame(frameOpts{proto: 17, sport: 5000, dport: 4789, withVNI: true, vni: 9999, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})},
		{"runt 14B", make([]byte, 14)},
		{"runt 20B", make([]byte, 20)},
	}
}

// TestMatchBPFDifferential is the core correctness check for bpfmatch.Match:
// every filter and every packet, the verdict from the Go cBPF interpreter and
// the verdict from the compiled-and-executed eBPF must agree.
//
// This checks our integration against an independent implementation rather
// than against our own expectations, which is the only way to have real
// confidence in a translation layer.
func TestMatchBPFDifferential(t *testing.T) {
	requireBPF(t)

	pkts := bpfPackets()
	var comparisons int
	for _, tc := range bpfCorpus {
		t.Run(tc.expr, func(t *testing.T) {
			ins := cbpf(t, tc.raw)
			vm, err := bpf.NewVM(ins)
			if err != nil {
				t.Fatalf("cBPF VM: %v", err)
			}
			m := bpfmatch.Match(tc.expr, ins)
			for _, p := range pkts {
				n, verr := vm.Run(p.pkt)
				// Do not fold an interpreter error into "no match": that would
				// score a genuine disagreement as a pass, which is exactly the
				// failure this whole test exists to catch.
				if verr != nil {
					t.Fatalf("%s: cBPF interpreter failed, so it cannot be an oracle: %v", p.name, verr)
				}
				want := n != 0
				got := mustMatch(t, p.pkt, afxdp.WithFilter(m))
				comparisons++
				if got != want {
					t.Errorf("%s: cBPF says %v, compiled eBPF says %v", p.name, want, got)
				}
			}
		})
	}
	t.Logf("%d filter/packet comparisons", comparisons)
}

// TestMatchBPFMultiBuffer checks every corpus filter also loads with
// BPF_F_XDP_HAS_FRAGS, which WithMultiBuffer needs.
func TestMatchBPFMultiBuffer(t *testing.T) {
	requireBPF(t)

	for _, tc := range bpfCorpus {
		t.Run(tc.expr, func(t *testing.T) {
			m := bpfmatch.Match(tc.expr, cbpf(t, tc.raw))
			// WithMultiBuffer makes MatchPacket load the program with
			// BPF_F_XDP_HAS_FRAGS, exactly as Open would.
			pkt := buildFrame(frameOpts{proto: 6, sport: 1, dport: 22, srcIP: "192.0.2.9", dstIP: "192.0.2.2"})
			if _, err := afxdp.MatchPacket(pkt, afxdp.WithFilter(m), afxdp.WithMultiBuffer()); err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					t.Fatalf("rejected under xdp.frags:\n%+v", ve)
				}
				t.Fatalf("MatchPacket with WithMultiBuffer: %v", err)
			}
		})
	}
}

// TestDualFamilyPorts pins the intentional behavior change: the port builders
func TestMatchBPFErrors(t *testing.T) {
	requireBPF(t)

	for _, tc := range []struct {
		name   string
		match  afxdp.Match
		expect string
	}{
		{"empty", bpfmatch.Match("empty", nil), "at least one"},
		{"bad-jump", bpfmatch.Match("badjump", []bpf.Instruction{
			bpf.Jump{Skip: 99}, bpf.RetConstant{Val: 1},
		}), "badjump"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := afxdp.MatchPacket(make([]byte, 60), afxdp.WithFilter(tc.match))
			if err == nil {
				t.Fatal("bad cBPF program was accepted")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not contain %q", err, tc.expect)
			}
		})
	}
}

// TestMatchBPFAcceptsRawInstructions pins the documented workflow: the packed
// form that "tcpdump -ddd" and pcap_compile produce is bpf.RawInstruction, and
// the cBPF-to-eBPF compiler does not accept it. Match decodes it, so callers
// do not have to remember to Disassemble — the documented path has to work
// exactly as written.
func TestMatchBPFAcceptsRawInstructions(t *testing.T) {
	requireBPF(t)

	for _, tc := range bpfCorpus {
		t.Run(tc.expr, func(t *testing.T) {
			// Feed the raw form straight through, as the docs describe.
			raw := make([]bpf.Instruction, len(tc.raw))
			for i, r := range tc.raw {
				raw[i] = r
			}
			pkt := buildFrame(frameOpts{proto: 6, sport: 1234, dport: 22, srcIP: "192.0.2.9", dstIP: "192.0.2.2"})
			fromRaw, err := afxdp.MatchPacket(pkt, afxdp.WithFilter(bpfmatch.Match(tc.expr, raw)))
			if err != nil {
				t.Fatalf("raw instructions rejected: %v", err)
			}
			// ...and it must agree with the disassembled form.
			fromDecoded := mustMatch(t, pkt, afxdp.WithFilter(bpfmatch.Match(tc.expr, cbpf(t, tc.raw))))
			if fromRaw != fromDecoded {
				t.Errorf("raw gave %v, decoded gave %v", fromRaw, fromDecoded)
			}
		})
	}

	// An opcode nothing can decode is reported, not attached.
	bad := []bpf.Instruction{bpf.RawInstruction{Op: 0x9f, Jt: 0, Jf: 0, K: 0}}
	if _, err := afxdp.MatchPacket(make([]byte, 60), afxdp.WithFilter(bpfmatch.Match("bogus", bad))); err == nil {
		t.Error("an unrecognised cBPF opcode was accepted")
	} else if !strings.Contains(err.Error(), "unrecognised cBPF opcode") {
		t.Errorf("error %q does not explain the problem", err)
	}

	// An empty desc gets a usable default rather than an empty string.
	m := bpfmatch.Match("", cbpf(t, bpfCorpus[0].raw))
	if _, err := afxdp.MatchPacket(make([]byte, 60), afxdp.WithFilter(m)); err != nil {
		t.Fatalf("empty desc: %v", err)
	}
}

// TestExceptMatchAll checks the degenerate case now reported plainly: an
// exception matching everything passes every packet to the kernel, leaving the
// --- helpers -----------------------------------------------------------

var (
	probeOnce sync.Once
	probeErr  error
)

// requireBPF skips the whole test once when this environment cannot load and
// run BPF programs. Deliberately not inside the table loops: a per-case skip
// would let the suite report green while testing nothing, which for a
// translation layer is the worst possible outcome.
func requireBPF(t *testing.T) {
	t.Helper()
	probeOnce.Do(func() {
		if err := rlimit.RemoveMemlock(); err != nil {
			probeErr = fmt.Errorf("cannot raise memlock: %w", err)
			return
		}
		if _, err := afxdp.MatchPacket(make([]byte, 14), afxdp.WithFilter(afxdp.MatchUDPPort(5000))); err != nil {
			probeErr = fmt.Errorf("cannot load and test-run BPF programs here: %w", err)
		}
	})
	if probeErr != nil {
		t.Skipf("skipping: %v", probeErr)
	}
}

// mustMatch runs pkt through a filter and fails on any error, printing the
// verifier listing when there is one (%v alone truncates it to one line).
func mustMatch(t *testing.T, pkt []byte, opts ...afxdp.Option) bool {
	t.Helper()
	got, err := afxdp.MatchPacket(pkt, opts...)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected the filter:\n%+v", ve)
		}
		t.Fatalf("MatchPacket: %v", err)
	}
	return got
}

// --- packet construction (a copy of the root package's test helper; the
// two are separate modules and cannot share test code) ---

// TCP flag bits, as they sit in the single byte at offset 13 of the TCP header.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpACK = 0x10
)

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

// TestVNIExpressionIntent pins the *meaning* of the VXLAN VNI corpus entry,
// not just interpreter/eBPF agreement. The differential harness cannot catch a
// filter that is internally consistent but semantically wrong — this corpus
// entry once compared the VNI against a value shifted left by one byte, and
// every differential case still passed, because both sides faithfully executed
// the wrong filter. udp[12:4] loads the three VNI bytes plus the reserved
// byte, so VNI 1234 (0x0004d2) masked with 0xffffff00 must equal 0x0004d200.
func TestVNIExpressionIntent(t *testing.T) {
	requireBPF(t)

	var m afxdp.Match
	for _, tc := range bpfCorpus {
		if strings.Contains(tc.expr, "0xffffff00") {
			m = bpfmatch.Match(tc.expr, cbpf(t, tc.raw))
		}
	}
	right := buildFrame(frameOpts{proto: 17, sport: 5000, dport: 4789, withVNI: true, vni: 1234, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})
	wrong := buildFrame(frameOpts{proto: 17, sport: 5000, dport: 4789, withVNI: true, vni: 9999, srcIP: "192.0.2.1", dstIP: "192.0.2.2"})
	if !mustMatch(t, right, afxdp.WithFilter(m)) {
		t.Error("VNI 1234 did not match the expression documented as matching VNI 1234")
	}
	if mustMatch(t, wrong, afxdp.WithFilter(m)) {
		t.Error("VNI 9999 matched the VNI-1234 expression")
	}
}
