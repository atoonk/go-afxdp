package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestIPChecksum checks ipChecksum against the canonical worked example from
// the IPv4 header checksum literature: header 4500 0073 0000 4000 4011 ....
// with the checksum field zeroed must produce 0xb861.
func TestIPChecksum(t *testing.T) {
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := ipChecksum(hdr); got != 0xb861 {
		t.Fatalf("ipChecksum = 0x%04x, want 0xb861", got)
	}
}

func TestBuildReply(t *testing.T) {
	// A request header: client MAC/IP/port -> our MAC/IP:53.
	var req [udpPayloadOff]byte
	copy(req[ethDst:], []byte{0xaa, 0, 0, 0, 0, 0x01})  // our MAC (dst of request)
	copy(req[ethSrc:], []byte{0xbb, 0, 0, 0, 0, 0x02})  // client MAC (src)
	req[14] = 0x45                                      // IPv4, IHL 5
	req[23] = 17                                        // UDP
	copy(req[ipSrc:], []byte{192, 168, 0, 50})          // client IP
	copy(req[ipDst:], []byte{192, 168, 0, 1})           // our IP
	binary.BigEndian.PutUint16(req[udpSrcPort:], 40000) // client port
	binary.BigEndian.PutUint16(req[udpDstPort:], 53)    // to :53

	answer := []byte("this-is-a-dns-answer-payload")
	out := make([]byte, 2048)
	n := buildReply(req[:], answer, out)

	if want := udpPayloadOff + len(answer); n != want {
		t.Fatalf("length = %d, want %d", n, want)
	}
	// Addresses reversed at every layer.
	if !bytes.Equal(out[ethDst:ethDst+6], req[ethSrc:ethSrc+6]) {
		t.Error("eth dst should be the client MAC")
	}
	if !bytes.Equal(out[ethSrc:ethSrc+6], req[ethDst:ethDst+6]) {
		t.Error("eth src should be our MAC")
	}
	if !bytes.Equal(out[ipSrc:ipSrc+4], req[ipDst:ipDst+4]) {
		t.Error("ip src should be our IP")
	}
	if !bytes.Equal(out[ipDst:ipDst+4], req[ipSrc:ipSrc+4]) {
		t.Error("ip dst should be the client IP")
	}
	if got := binary.BigEndian.Uint16(out[udpSrcPort:]); got != 53 {
		t.Errorf("udp src port = %d, want 53", got)
	}
	if got := binary.BigEndian.Uint16(out[udpDstPort:]); got != 40000 {
		t.Errorf("udp dst port = %d, want 40000", got)
	}
	// Lengths.
	if got := binary.BigEndian.Uint16(out[ipTotalLen:]); got != uint16(20+8+len(answer)) {
		t.Errorf("ip total length = %d, want %d", got, 20+8+len(answer))
	}
	if got := binary.BigEndian.Uint16(out[udpLen:]); got != uint16(8+len(answer)) {
		t.Errorf("udp length = %d, want %d", got, 8+len(answer))
	}
	// Payload.
	if !bytes.Equal(out[udpPayloadOff:n], answer) {
		t.Error("payload mismatch")
	}
	// The IPv4 header checksum must verify: summing the header (checksum field
	// included) gives 0xffff, i.e. recomputing with it zeroed reproduces it.
	saved := make([]byte, 2)
	copy(saved, out[ipChecksumOff:ipChecksumOff+2])
	out[ipChecksumOff], out[ipChecksumOff+1] = 0, 0
	if got := ipChecksum(out[14:34]); got != binary.BigEndian.Uint16(saved) {
		t.Errorf("ip checksum %04x doesn't verify (recomputed %04x)", binary.BigEndian.Uint16(saved), got)
	}
}
