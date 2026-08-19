# Custom match examples

Six runnable programs, each writing its own in-kernel packet filter with
`afxdp.NewMatch`.

**Most people should not need any of this.** Try the built-in matchers first,
then a tcpdump expression via the
[`pcapfilter`](../../pcapfilter) module, which covers `and`/`or`/`not`, port
ranges, TCP flags, VLAN IDs, MAC addresses and arbitrary byte offsets. `NewMatch`
is the layer below both, for the cases neither reaches.

Start with **udpsrcport**: it is the shortest, and it is a tutorial rather than a
tool — the built-in `MatchUDPSrcPort` does the same thing in one line and covers
IPv6 too. The rest each capture something no built-in expresses.

Then read **[`gre`](gre)**, which is the one that shows the whole picture: a
custom match built from the exported API, arguments validated through
`MatchError` so `Open` reports them, and — in `main_test.go` — the matcher run
against crafted packets with `afxdp.MatchPacket`, no NIC involved. If you write
one of these, write that test too. Hand-written eBPF fails silently.

| Example | Captures | The technique it shows |
|---------|----------|------------------------|
| [`udpsrcport`](udpsrcport) | IPv4/UDP by source port — *tutorial only, use `MatchUDPSrcPort`* | the basic shape of a custom match |
| [`tcpsyn`](tcpsyn) | TCP connection openers (SYN set, ACK clear) | a **masked** compare, not just equality |
| [`vlan`](vlan) | one 802.1Q VLAN by ID | reading from the **raw frame start**, and byte-swapped masks |
| [`dstmac`](dstmac) | frames addressed to one MAC | a **6-byte** field across two compares |
| [`vxlan`](vxlan) | one VXLAN tunnel by VNI | three conditions **ANDed** in one block |
| [`gre`](gre) | one GRE tunnel by key | a **masked flags** check, a 32-bit compare, and **a unit test** |

Build and run any of them the same way:

```
go build -o vxlan ./examples/customfilter/vxlan
sudo ./vxlan -iface eth0 -vni 1234
```

All of them need `CAP_BPF` and `CAP_NET_ADMIN` (or just run as root) and enough
locked memory. Each takes `-iface`; run with `-h` for the rest.

Every example passes `WithKeepManagement()`, which keeps ARP, IPv6 ND, SSH and
DNS replies addressed to this host with the kernel. That is what makes them safe
to run on the interface you are logged in through — without it a broad filter
can take your own session away from the kernel and lock you out.

## Three things to know before writing your own

**`FrameBase()` vs `Data`.** `e.FrameBase()` gives you a base with a single
802.1Q tag already stepped over, so your offsets work whether or not the NIC
stripped the tag — that is what you want for anything at L3 or above, and it is
what every built-in matcher uses. But it means the tag itself, and the MAC
addresses that precede it, are not where you would expect. Match those from
`e.Data`, the raw frame start, as `vlan` and `dstmac` do. Getting this wrong
reads four bytes off on tagged frames, which still verifies and still matches
*something*, so it is worth being deliberate about.

**Byte order.** eBPF loads are little-endian; the packet is big-endian. The rule
that covers every case: **build the expected value the way the load sees it.**
`afxdp.NetShort` does that for 16-bit fields, and it applies to masks as much as
to values — `vlan` masks with `NetShort(0x0fff)`, not `0x0fff`. Wider fields need
it by hand: see `vniLE` in `vxlan` for 24 bits and the `lo`/`hi` pair in `dstmac`
for 48. Single-byte fields (IP protocol, TCP flags) need nothing. A byte-order
slip is the most likely bug in a custom match and the hardest to spot, because
the filter loads fine and simply matches the wrong traffic.

**`Imm` vs `Imm32` on 32-bit compares.** Comparing a 32-bit load needs
`JEq.Imm32`/`JNE.Imm32`, not `.Imm`. The `.Imm` forms compare 64 bits, so an
expected value with its high bit set is sign-extended to a negative number while
the packet load is zero-extended, and the two are never equal — the matcher
verifies, attaches, and never fires. `dstmac` uses `Imm32` for exactly this
reason. 16-bit and 8-bit loads are unaffected; `.Imm` is right for those.

Every matcher here is regression-tested against crafted packets in
`filter_custom_test.go` in the repository root, in `TestCustomMatchExamples`.
Those copies are kept in sync by hand — if you change an example, change the
test too.

## Testing your own

`afxdp.MatchPacket` runs a filter against a packet you supply and reports
whether it would be redirected, using the same eBPF `Open` would attach:

```go
func TestMyMatcher(t *testing.T) {
    // Needs CAP_BPF + CAP_NET_ADMIN (or root); once per binary:
    //   rlimit.RemoveMemlock()

    frame := udpFrame("10.0.0.1", 53, "10.0.0.2", 4000) // build it yourself, see below
    ok, err := afxdp.MatchPacket(frame, afxdp.WithFilter(myMatch))
    if err != nil {
        // Do NOT just skip here. The kernel reports a verifier rejection as
        // EACCES, so a broken matcher and a missing capability both look like
        // "permission denied" — unwrap to tell them apart, or a matcher that
        // does not even load reports green.
        var ve *ebpf.VerifierError
        if errors.As(err, &ve) {
            t.Fatalf("filter rejected:\n%+v", ve) // the matcher is wrong
        }
        t.Skipf("cannot run BPF here: %v", err) // this machine can't check
    }
    if !ok {
        t.Error("did not match a frame it should have")
    }
}
```

Pair every positive with a near miss — the same frame with one field changed.
A byte-order or offset mistake usually still matches something, so a matcher
tested only against packets it should accept looks correct until it ships.

You need frames to test against. There is no helper for this in the library;
build them by hand, which for Ethernet/IPv4/UDP is about fifteen lines:

```go
func udpFrame(src string, sport int, dst string, dport int) []byte {
    b := []byte{
        0x02, 0, 0, 0, 0, 0x01, // dst MAC
        0x02, 0, 0, 0, 0, 0x02, // src MAC
        0x08, 0x00, // EtherType: IPv4
    }
    ip := make([]byte, 20)
    ip[0] = 0x45 // version 4, IHL 5 (no options)
    binary.BigEndian.PutUint16(ip[2:], 20+8)
    ip[8], ip[9] = 64, 17 // TTL, protocol UDP
    copy(ip[12:], net.ParseIP(src).To4())
    copy(ip[16:], net.ParseIP(dst).To4())

    udp := make([]byte, 8)
    binary.BigEndian.PutUint16(udp[0:], uint16(sport))
    binary.BigEndian.PutUint16(udp[2:], uint16(dport))
    binary.BigEndian.PutUint16(udp[4:], 8)

    return append(append(b, ip...), udp...)
}
```

Checksums are not needed: XDP runs before any checksum validation, and these
matchers never look at them. For a tagged frame, splice `0x81, 0x00` plus the
two TCI bytes in after the MACs and before the EtherType. `filter_custom_test.go`
in the repository root has a fuller version handling VLAN, IPv6, TCP flags and
VXLAN, worth copying if you need those.

## Where the offsets come from

All of these assume an IPv4 header with no options, the same simplification the
built-in matchers make.

From `e.Data`, the raw frame start — the only place the MACs and the VLAN tag
are reliably found:

```
 0   dst MAC (6)
 6   src MAC (6)
12   TPID (2) = 0x8100 if tagged, then TCI (2) at 14, VLAN ID = low 12 bits
```

From the base `FrameBase()` returns, which is `e.Data` on an untagged frame and
`e.Data+4` on a tagged one:

```
12   EtherType (2)      = afxdp.OffEtherType
14   IPv4 header (20)   -> protocol at 23, src IP at 26, dst IP at 30
34   L4 header          -> src port 34, dst port 36
                          TCP flags at 47, UDP payload at 42
```

For IPv6 the header is a fixed 40 bytes:

```
12   EtherType (2)      = 0x86DD
14   IPv6 header (40)   -> Next Header at 20, src at 22, dst at 38
54   L4 header          -> src port 54, dst port 56
```

And for VXLAN, which sits inside IPv4/UDP port 4789:

```
42   VXLAN header (8)   -> flags at 42, VNI at 46 (3 bytes), reserved at 49
50   inner Ethernet frame
```

"Fixed" is doing work in both cases. IPv4 with options and IPv6 with extension
headers put L4 somewhere else, and none of these example matchers check for
that — worse than not matching, a packet with options can *false-match* if the
bytes at the fixed offset happen to look like the port you asked for. The
built-in matchers guard against this (they require IHL=5 and reject non-initial
fragments before any L4 read); if you copy one of these examples into real use,
copy that guard too — five instructions, see `ipv4FixedL4Guard` in `filter.go` —
or use the cBPF layer, which computes the header length. The same goes for
stacked QinQ tags: `FrameBase` unwinds one 802.1Q tag, not two.
