# go-afxdp

A small, easy to use Go library for **AF_XDP** sockets. It moves packets between
a NIC and userspace at high rates, bypassing the kernel network stack, for
DPDK-like speeds with the convenience of ordinary Go.

```go
import "github.com/atoonk/go-afxdp"
```

It binds every rx queue for you, installs an in-kernel filter so you only take
the traffic you want, auto-selects zero copy where the driver supports it, and is
safe to drive from a receive and a transmit goroutine at once. It is a
friendlier, concurrency-safe fork of [`asavie/xdp`](https://github.com/asavie/xdp).

New to AF_XDP? It is a different beast from `net.UDPConn`. Read
[How AF_XDP works](#how-af_xdp-works-and-why-theres-a-filter) for the one-minute
mental model (especially *why there is a filter*), then come back.

**Performance:** about 13 Mpps transmitting 64-byte frames from
userspace Go on one Intel ixgbe NIC, roughly 92% of 10G line rate.

**Status:** validated on Intel ixgbe (zero copy) and AWS ENA. The API is still
settling, so expect minor changes before a v1.0 tag.

## Install

```
go get github.com/atoonk/go-afxdp
```

Linux, Go 1.22+, and `CAP_NET_RAW` (or root) with enough locked memory
(`ulimit -l`) for the BPF maps and UMEM.

## Quick start

### Receive

Pick the traffic you want with a filter, open the interface, read packets. `Open`
attaches the XDP program, binds one socket per rx queue, and registers them, all
in one call.

```go
fleet, err := afxdp.Open("eth0", afxdp.WithUDPPorts(4789)) // capture UDP/4789
if err != nil {
    log.Fatal(err)
}
defer fleet.Close()

for _, xsk := range fleet.Sockets() {
    go func(xsk *afxdp.Socket) {
        for {
            xsk.Fill(xsk.NumFreeFillSlots()) // give the kernel buffers
            n, _ := xsk.Poll(-1)             // block until packets arrive
            descs := xsk.Receive(n)
            for _, d := range descs {
                frame := xsk.GetFrame(d)     // the received bytes
                _ = frame
            }
            xsk.Recycle(descs)               // return frames to be filled again
        }
    }(xsk)
}
```

The whole receive model is **Fill, Poll, Receive, Recycle**. Only UDP/4789
reaches your sockets; everything else (SSH included) keeps flowing through the
kernel normally.

### Transmit

Hand `SendBatch` (or `SendFunc`) your packets and it does the ring bookkeeping for
you, reclaiming sent frames, kicking the kernel, never stalling on a full ring.
Just call it in a loop.

```go
fleet, _ := afxdp.Open("eth0", afxdp.WithFilter(afxdp.MatchNone())) // transmit only
xsk := fleet.Sockets()[0]
for {
    n, err := xsk.SendBatch(packets) // returns how many were queued this call
    ...
}
```

A filter is required, `Open` returns an error without one, so you cannot
accidentally redirect every packet and cut off your own box. Pass
`WithUDPPorts`/`WithFilter` for specific traffic, `MatchAll()` to take everything
on purpose, or `MatchNone()` for transmit only.

## How AF_XDP works (and why there's a filter)

If you have only used `net.UDPConn` and friends, AF_XDP works differently enough
to be worth a paragraph before you start.

A normal socket (the `AF_INET` family) hands you data *after* the kernel's network
stack has processed the packet. **AF_XDP** is its own socket family that receives
raw Ethernet frames straight from the **driver**, before the stack, and that is
where the speed comes from.

But the driver has to be told *which* frames go to your socket instead of up the
normal stack. That decision is an **XDP program**, a small eBPF program that runs
in the driver on every received packet and returns either `XDP_PASS` (let the
kernel handle it normally) or `XDP_REDIRECT` (hand it to an AF_XDP socket). So
receiving with AF_XDP is always two pieces working together, the socket, and an
eBPF/XDP filter that redirects the traffic you want into it.

Writing, compiling, and loading that eBPF is the part most libraries leave to you.
**This library installs it for you.** `WithUDPPorts(53)` (or the more general
`WithFilter(...)`) compiles to the XDP program, attaches it to the interface, and
points its redirect at your sockets. Everything that does not match keeps flowing
up the normal kernel stack untouched. Transmit is the mirror image, you write
frames into shared memory (the UMEM) and the driver sends them.

The takeaway: a filter is not an optional extra. For receive it is *how packets
reach an AF_XDP socket at all*, so choosing it is the main thing you configure.
(`MatchNone` covers the transmit-only case, where you want the datapath but no
redirect.)

**Seeing what's installed.** `Fleet.Info()` reports the active filter and mode
(`... filter udp/53`). From a shell, `ip link show <iface>` shows whether an XDP
program is attached, and `bpftool net show dev <iface>` lists it. If expected
traffic is not arriving, check that `Info().Filter` matches it and that `Stats()`
is not reporting `rx_ring_full`/`fill_empty`, which mean the rings could not keep
up.

## When to use AF_XDP

AF_XDP is for when you need packets **in userspace**. If all you do is reflect,
forward, drop, or mirror packets, do it in the XDP program itself (`XDP_TX`,
`bpf_redirect()`, `XDP_DROP`), it stays in the driver and is faster than a
userspace round trip. Reach for AF_XDP when the per-packet logic does not fit in
eBPF: crypto and tunnels (WireGuard, IPsec, QUIC), a userspace TCP/TLS or
app-protocol stack, stateful deep packet inspection, traffic generation, or
anything that needs real Go libraries. The sweet spot is to let XDP cheaply pass
the bulk to the kernel and lift only the flows you care about up to Go.

## Performance

Two bare-metal boxes, AMD EPYC 9275F (24 cores / 48 threads), 100 Gbit/s Mellanox
ConnectX (`mlx5_core`) with 48 combined queues, native XDP and zero-copy on both
ends. [`examples/blast`](examples/blast) on one, [`examples/drop`](examples/drop)
on the other, over a tagged VLAN.

| frame size | sent | received | TX cores | RX cores |
| --- | --- | --- | --- | --- |
| 1500 B | 8.20 Mpps, 99.9 Gbit/s | 8.18 Mpps, 99.7 Gbit/s, no drops | 18 | 17 |
| 64 B | 140 Mpps, 98.5 Gbit/s | 119 Mpps, 83.6 Gbit/s | 23 | 21 |

With 1500-byte frames this fills a 100G link in both directions and loses nothing.

With 64-byte frames the sender reaches about 98% of line rate. The receiver takes
119 Mpps of it and the missing 21 Mpps never reach the rings: the receiving NIC
discards them itself (`rx_discards_phy`) because it cannot DMA into host memory
that fast. The wire delivered 100.00% of what was sent, our fill ring ran dry
7,033 times out of 3.5 billion packets, and nothing was dropped at the application
level — so that ceiling is the card's, not this library's.

Cores are userspace CPU of the example process on a 48-thread box; driver and
softirq work sits on top (the machines ran 80–99% busy at these rates). Packet
generation is included in the TX figure and is a small part of it: a variant of
`blast` with the frames pre-built uses 22.0 cores instead of 22.8, so building
each packet costs roughly 3% of the send path.

### Scaling per queue

One socket and one goroutine per queue, so queue count is roughly core count.
Setting the NIC to N queues on both ends with `ethtool -L eno2 combined N`
(reset the RSS table first with `ethtool -X eno2 equal N`, or the change is
refused), 64-byte frames:

| queues | sent | TX cores | received | RX cores | pkt/poll |
| --- | --- | --- | --- | --- | --- |
| 1 | 13.6 Mpps | 1.0 | 7.7 Mpps | 0.5 | 64 |
| 2 | 26.2 Mpps | 2.0 | 15.3 Mpps | 0.7 | 64 |
| 4 | 51.5 Mpps | 4.0 | 34.0 Mpps | 1.6 | 64 |
| 8 | 95.2 Mpps | 8.0 | 73.6 Mpps | 2.3 | 64 |
| 16 | 141.3 Mpps | 16.0 | 116.9 Mpps | 4.0 | 64 |
| 32 | 139.5 Mpps | 22.4 | 118.4 Mpps | 5.0 | 78 |
| 48 | 138.9 Mpps | 22.7 | 118.8 Mpps | 5.7 | 92 |

Transmit scales linearly at about **13.6 Mpps per core** and reaches line rate at
16 queues. Receive costs far less userspace CPU because the expensive half — the
driver's NAPI poll and the XDP redirect — runs in softirq, not in the process;
a single queue tops out near 7.7 Mpps while our loop consumes it with half a core.

**More queues is not better.** Past 16 nothing gets faster — transmit is at line
rate and receive is at the NIC's limit — but the receiver keeps costing more CPU.
Measured box-wide, 16 queues carried 116 Mpps using 19.5 of 48 cores, while 48
queues carried 119 Mpps using 24.2 — noticeably more machine for 2% more
throughput.

### NAPI batching (done for you)

Left alone, the kernel wakes an AF_XDP receiver once per NAPI poll, and at these
rates that is millions of times a second — far more often than it needs to. The
receiver then burns its CPU on syscall entry and poll machinery instead of on
packets: profiling the 48-queue sink put `os_xsave`, `sock_poll`, `eventfd_poll`
and interrupt dispatch at the top, with the functions that actually move packets
(`__xsk_map_redirect`, `__xsk_rcv_zc`) nowhere near it.

**`Open` fixes this for you.** On a native-mode NIC it sets
`napi_defer_hard_irqs=2` and `gro_flush_timeout=200µs` so the kernel lets packets
accumulate, and restores your previous values on `Close`. Same traffic, same
118.8 Mpps, on the 100G Mellanox sink:

| | packets per poll | polls/s | box busy |
| --- | --- | --- | --- |
| kernel default | 39 | 3.0M | 36.5 of 48 cores |
| what `Open` applies | 92 | 1.3M | **24.2 of 48 cores** |

Same throughput for **about a third less of the machine**, which is why this is on
by default rather than a tuning tip. (A trivial filter that does no per-packet
work benefits even more; the numbers above are a realistic UDP sink.)
`Fleet.Info()` reports it (`napi defer=2 flush=200µs`) so it is never invisible.

Worth knowing, since these are properties of the interface rather than of your
process:

- They are restored on `Close`, but **a crash leaves them applied**. To reset by
  hand: `echo 0 > /sys/class/net/<iface>/napi_defer_hard_irqs` and the same for
  `gro_flush_timeout`.
- Deferring can hold a packet for up to the flush timeout when traffic is sparse,
  so it trades a little idle latency for a lot of loaded throughput.
- Generic/SKB mode is never touched, so veth and test setups are unaffected.
- Opt out with `WithoutAutoTune()`, or change the values with
  `WithNAPITuning(deferIRQs, flush)`. Do not raise them much: at `10` and `500µs`
  the same sink fell to 77 Mpps with 29M discards a second, because NAPI stopped
  running often enough.

Interrupt coalescing (`ethtool -C rx-usecs`) does *not* substitute for this —
most wakeups here are NAPI flushes rather than hardware interrupts, so raising
`rx-usecs` changed nothing at all.

One curiosity this explains: untuned, throughput becomes oddly sensitive to how
long the XDP program takes, and a filter that reads packet headers batches better
— and so runs *faster* — than one that does nothing. Tuned, that inversion
disappears and the simplest program is the cheapest, as it should be.

### Queue count

Tune this on the NIC, not in the application. Reduce the channel count so RSS only
spreads over the queues you want, and keep binding all of them (the default):

```
ethtool -X eno2 equal 16      # shrink the RSS table first
ethtool -L eno2 combined 16   # then the channels
```

Using `WithQueues(16)` while the NIC still has 48 RSS queues does something quite
different and usually wrong: the flows hashed to the other 32 queues have no socket
bound, so the XDP program passes them to the kernel and your application never sees
them. You cannot choose which queue a flow lands on, which is why binding every
available queue is the default.

## Filtering

A filter decides which packets are handed to your sockets. Only matching packets
go to userspace; everything else continues to the normal kernel stack. That is
what lets you run on a live interface without stealing SSH or unrelated traffic,
and it is why `Open` requires one.

The shorthand for UDP:

```go
fleet, _ := afxdp.Open("eth0", afxdp.WithUDPPorts(4789)) // VXLAN, say
```

For anything richer, `WithFilter` takes a set of **matches**, and a packet is
redirected if it satisfies **any** of them (logical OR):

```go
// WireGuard on two ports, plus let ping through:
afxdp.Open("eth0", afxdp.WithFilter(
    afxdp.MatchUDPPort(51820, 51821),
    afxdp.MatchICMPEcho(),
))

// A VXLAN tunnel endpoint and its BGP session:
afxdp.Open("eth0", afxdp.WithFilter(
    afxdp.MatchUDPPort(4789),
    afxdp.MatchTCPPort(179),
))

// All GRE and all ESP (IPsec), regardless of ports:
afxdp.Open("eth0", afxdp.WithFilter(
    afxdp.MatchIPProto(47),
    afxdp.MatchIPProto(50),
))

// Anything to or from a subnet, by CIDR (IPv4 or IPv6):
afxdp.Open("eth0", afxdp.WithFilter(
    afxdp.MatchSrcIP("10.0.0.0/8"),
    afxdp.MatchDstIP("10.0.0.0/8"),
))
afxdp.Open("eth0", afxdp.WithFilter(afxdp.MatchDstIP("2001:db8::/32")))

// One flow, src AND dst (both directions, OR the two halves):
afxdp.Open("eth0", afxdp.WithFilter(
    afxdp.MatchFlow("10.0.0.1/32", "10.0.0.2/32"),
    afxdp.MatchFlow("10.0.0.2/32", "10.0.0.1/32"),
))
```

Match builders:

| Builder | Matches |
|---------|---------|
| `MatchUDPPort(ports...)` | IPv4/UDP to these dest ports (no ports = all UDP) |
| `MatchTCPPort(ports...)` | IPv4/TCP to these dest ports (no ports = all TCP) |
| `MatchICMPEcho()` | IPv4 ICMP echo request (ping) |
| `MatchIPProto(proto)` | any IPv4 with this protocol number (47 GRE, 50 ESP, ...) |
| `MatchSrcIP(cidr)` | source IP in this CIDR, IPv4 or IPv6 (e.g. `10.0.0.0/8`, `2001:db8::/32`) |
| `MatchDstIP(cidr)` | destination IP in this CIDR, IPv4 or IPv6 |
| `MatchFlow(src, dst)` | src CIDR **and** dst CIDR together, i.e. one direction of a flow |
| `MatchEtherType(et)` | this EtherType (`0x0806` ARP, `0x86DD` IPv6, ...) |
| `MatchAll()` | every packet, the deliberate "take everything" |
| `MatchNone()` | nothing, attach without redirecting (e.g. zero copy TX for a sender) |

That is every builder. The options that install them, and the one exception to
them, are:

| Option | Effect |
|--------|--------|
| `WithFilter(matches...)` | redirect packets matching **any** of these builders |
| `WithUDPPorts(ports...)` | shorthand for `WithFilter(MatchUDPPort(ports...))` |
| `WithKeepManagement(extraTCPPorts...)` | the inverse: keep ARP, IPv6 ND, SSH and DNS replies *out* of the capture so a broad filter cannot lock you out of the box ([below](#keeping-your-session-alive-withkeepmanagement)) |

Each match is compiled to eBPF instructions with
[`github.com/cilium/ebpf/asm`](https://pkg.go.dev/github.com/cilium/ebpf/asm) into
a single XDP program, loaded and checked by the kernel verifier (the test suite
loads every builder and a composite to prove they verify).

A few things to know. Matches combine with OR, a packet is redirected if it
matches any of them. The one built-in AND is `MatchFlow`, which requires a src
CIDR and a dst CIDR together; arbitrary AND across the other builders is not
expressible as a single filter. The port, proto, and ICMP matchers
are IPv4 only and assume no IP options, the common case; the IP
(CIDR) matchers handle both IPv4 and IPv6 and read fixed offsets, so they are not
bothered by IP options or IPv6 extension headers. Every matcher transparently
skips a single 802.1Q VLAN tag, so the same filter works whether or not the NIC
strips the tag before XDP — stacked QinQ tags are not unwound. For classification
beyond these builders, redirect everything and classify in your receive loop.

### Keeping your session alive: `WithKeepManagement`

`MatchAll()` on the NIC you are logged in through takes every packet away from the
kernel, including the ones carrying your session. `WithKeepManagement()` leaves
those with the kernel and captures the rest:

```go
fleet, err := afxdp.Open("eth0",
    afxdp.WithFilter(afxdp.MatchAll()), // capture everything...
    afxdp.WithKeepManagement(),         // ...except what keeps me logged in
)
```

What stays with the kernel:

| passed through | why |
| --- | --- |
| ARP, IPv6 ND (ICMPv6 133–137) | gateway MAC resolution |
| TCP to/from port 22, addressed to this interface | inbound and outbound SSH |
| UDP and TCP source port 53, addressed to this interface | DNS replies |

**ARP matters more than the SSH rule.** Pass SSH through but swallow ARP and the
box still goes dark: the kernel cannot refresh the gateway's link-layer address,
and about a minute later it can no longer reply to anything. That is the failure
this exists to prevent, and it is why the preset is not just "port 22".

The port rules are scoped to the addresses the interface has when `Open` is
called, so a router still captures transit traffic on port 22 — only traffic
addressed to this box is spared. Every address is covered, IPv4 and IPv6, however
many of each: a rule is emitted per address, and the address family selects the
header offsets. Addresses added later are not covered; reopen the fleet if they
change. Pass extra TCP ports for SSH on a non-standard port:
`WithKeepManagement(2222)`.

Two things to know. Traffic *from* port 22 or 53 to this host is not captured, so
a sender that picks those source ports evades the capture — irrelevant for
measurement, relevant if you are hunting an adversary. And if you administer the
box through a different NIC than the one you are capturing on, you do not need
this at all.

## Transmit

The easy way is `SendBatch` (copy your buffers in) or `SendFunc` (fill each frame
in place, no copy, ideal for a generator that varies a field per packet). Both
handle all the ring bookkeeping, so you just call them in a loop.

```go
// SendFunc fills each frame in place and returns the packet length.
for {
    _, err := xsk.SendFunc(256, func(i int, frame []byte) int {
        n := copy(frame, template)
        // offset 34 is the UDP source port (eth 14 + ip 20); vary it per packet
        binary.BigEndian.PutUint16(frame[34:], srcPort)
        srcPort++
        return n
    })
    if err != nil {
        // A length > FrameSize is a caller bug. Don't crash (or log unbounded)
        // inside a dataplane loop — log it rate-limited and keep going; see
        // the errLog helper in examples/blast.
    }
}
```

If you want full control, the primitives underneath are exported too,
**Alloc, build, Transmit, Complete**, plus `Kick` and `NumFreeTxSlots`. The one
rule if you hand-roll the loop: when the ring is full, still call `Kick`, or
copy-mode TX deadlocks (the kernel will not drain it on its own). `SendBatch` and
`SendFunc` handle that for you.

[`examples/blast`](examples/blast) is a line-rate generator built on `SendFunc`.

## Options and XDP mode

Everything is configured with functional options on `Open`:

| Option | Effect |
|--------|--------|
| `WithQueues(n)` | bind n rx queues, from queue 0 (0 or omitted = all) |
| `WithUDPPorts(p...)` | shorthand for `WithFilter(MatchUDPPort(p...))` |
| `WithFilter(m...)` | redirect packets matching any of the given matches |
| `WithNumFrames(n)` | total UMEM buffers, rx + tx (default 4096) |
| `WithFrameSize(n)` | bytes per buffer (default 2048; auto **4096** on ENA for zero copy) |
| `WithTxFrames(n)` | buffers reserved for transmit (default half) |
| `WithRingSize(n)` | all four ring sizes, power of two (default 2048) |
| `WithZeroCopy()` | require native zero copy, `Open` fails if unavailable |
| `WithDriverMode()` / `WithGenericMode()` | force native / generic attach (default: auto) |
| `WithMultiBuffer()` | let packets span several frames — jumbo support, costs zero copy |
| `WithOptions(o)` | drop in a full `Options` struct, then override fields |

By default `Open` picks the mode for you. It tries native zero copy, then native
copy, then generic copy, using the first the driver accepts, so you get the fast
path on a real NIC and it still works on veth without you choosing. `Fleet.Info()`
reports what was selected. You rarely need to override it; `WithGenericMode`
forces generic (and never blips the link), `WithDriverMode` forces native, and
`WithZeroCopy` requires zero copy.

Heads up: native XDP reinitializes the driver's rings, so attaching or detaching
it **blips the link**. On some 10G NICs (e.g. Intel ixgbe) the PHY then
renegotiates for several seconds before the carrier is back, during which nothing
can send or receive. So a native-mode program may sit idle for a few seconds at
startup; that is the link relinking, not a hang. (The `blast` example waits for
the link to come up first, for exactly this reason.) `WithGenericMode` does not
reset the link, which is handy for quick local tests.

`WithFrameSize(4096)` gives zero copy on drivers that need page-sized frames;
Open already applies it on AWS ENA (see below), so you rarely set it by hand.
Each socket has its own UMEM of `NumFrames * FrameSize` bytes, so memory scales
with the queue count; size `NumFrames` accordingly on many-queue NICs.

### Need Wakeup

`WithNeedWakeup()` binds with `XDP_USE_NEED_WAKEUP`, the recommended operating
mode for AF_XDP:

```go
fleet, err := afxdp.Open("eth0",
    afxdp.WithUDPPorts(4789),
    afxdp.WithNeedWakeup(),
)
```

With the flag set, the kernel parks idle RX/TX queues and asks for an explicit
wakeup through the AF_XDP ring flags instead of NAPI-polling in a loop (without
it, a buffer-starved driver can burn entire cores in ksoftirqd while forwarding
nothing — see the `WithNeedWakeup` doc comment for the gory details). The
library handles the waking for you: `Poll` wakes the receive path, and the
transmit path kicks the kernel as needed.

It also cuts transmit syscalls: when the ring flags show the driver awake and
draining (typical in zero-copy mode), `Transmit` skips the `sendto` kick
entirely. `Stats().Kicks` and `Stats().KicksSuppressed` show how often each
happens.

It is not the default only because it changes the kernel contract for
applications that drive the rings themselves rather than through `Poll`/`Kick`.
If you use the high-level API, turn it on.

## AWS EC2 / ENA

The `ena` driver (EC2, including the "network optimized" `*n`/`*gn` instances)
supports native XDP, but the MTU has to be right, and on driver versions before
2.17.0 the channel count too. Miss either and `Open` silently falls back to
**generic** XDP, which works but drops packets on the floor under load without
any counter showing it. `Fleet.Info()` tells you which mode you got; if it says
`generic` on ENA, check these:

1. **Lower the MTU.** Base XDP hands the program one contiguous, page-sized
   (4 KB) buffer per packet, so a 9001-byte jumbo frame doesn't fit and ENA
   rejects the attach. Set the MTU under ~3.5 KB:
   ```
   ip link set dev ens5 mtu 3000
   ```
   (EC2 defaults to jumbo 9001. This is the driver's single-buffer XDP limit,
   not a library choice.) If you actually need jumbo frames, `WithMultiBuffer()`
   plus the driver patch in [contrib/ena-jumbo/](contrib/ena-jumbo/) lifts this —
   at the cost of zero-copy, so lowering the MTU stays the faster option
   otherwise.

2. **Only on ENA older than 2.17.0: free up queues for XDP.** Those versions
   carved a dedicated transmit ring per channel out of the same fixed hardware
   queue budget as your normal channels, and refused a native attach unless
   channels were **≤ half** the maximum. ENA 2.17.0 added full queue
   utilization in XDP and the limit is gone: measured on 2.17.2g, full channels
   (4 of 4) give native zero-copy for both receive and transmit. Check your
   version first, and only halve the channels if it is below 2.17.0:
   ```
   ethtool -i ens5 | grep '^version'
   ethtool -L ens5 combined 2
   ```

**Zero copy** on ENA additionally needs page-sized (4096-byte) UMEM frames — with
the default 2048 the bind silently drops to native *copy* mode. Open handles this
for you: when it sees the `ena` driver it defaults `FrameSize` to 4096, so once
the MTU is right the banner reads `zero-copy, native XDP` with no code
change. (Pass `WithFrameSize` yourself only to override that. It costs twice the
UMEM per queue, which is why 4096 is an ena-only default, not the global one.)

These `ethtool`/`ip` settings are per-boot; re-apply after a reboot. They are NIC
config, so set them yourself rather than have the library reconfigure your
interface underneath you. (The frame-size default is the one thing the library
*can* safely pick for you, since it only changes its own UMEM, not your NIC.)

### Jumbo frames (multi-buffer)

By default a packet must fit one UMEM frame, which is what forces the MTU step
above. `WithMultiBuffer()` lets a packet span several frames instead: it loads
the XDP program with `BPF_F_XDP_HAS_FRAGS` (so it can attach at a jumbo MTU at
all) and binds the socket with `XDP_USE_SG` (without which the kernel silently
drops every multi-buffer packet).

Read chained packets with `ReceivePackets` rather than `Receive` — `Receive`
returns one `Desc` per *frame*, so a jumbo packet looks like several unrelated
descriptors. `SendBatch` splits oversized payloads for you.

```go
fleet, _ := afxdp.Open("ens5",
    afxdp.WithFilter(afxdp.MatchUDPPort(4789)),
    afxdp.WithMultiBuffer(),
)
xsk := fleet.Sockets()[0]

pkts := xsk.ReceivePackets(64)      // []Packet, each a []Desc in wire order
for _, p := range pkts {
    n := xsk.CopyOut(p, buf)        // or walk p's fragments to avoid the copy
    _ = buf[:n]
}
xsk.RecyclePackets(pkts)
```

**The trade-off:** a device reports its multi-buffer zero-copy limit as
`xdp-zc-max-segs`. Where that is 1 — which is every ENA today — the kernel
refuses an `XDP_USE_SG` bind in zero-copy mode, so `Open` settles for native
*copy*. On ENA you get jumbo **or** zero-copy, never both. Native copy still
beats the generic fallback comfortably, but if you don't need jumbo frames,
lowering the MTU and leaving this option off is faster. Check `Info().ZeroCopy`.

**On AWS this needs a driver patch.** A stale compile probe in the ENA driver
disables multi-buffer on current kernels, so XDP still won't attach at MTU 9001
no matter what this library does. A one-line fix, the reasoning behind it, and
step-by-step instructions are in [contrib/ena-jumbo/](contrib/ena-jumbo/).

Measured on two `c7gn.xlarge` (4 vCPU, 6.1 kernel, `blast` → `drop`, 64-byte
frames), showing why the mode matters:

| Receiver mode | Result |
|---------------|--------|
| generic XDP (default) | ~3.1M rx pps — silently loses ~25% of a 4M pps sender |
| native XDP (queues + MTU) | lossless, rx == tx, `nic=0 app=0` |
| native + zero copy (auto 4096 frames) | 5.0M pps flat |

With everything in place — halved channels, MTU ≤ 3502, and the auto-4096 frames
giving a `zero-copy, native XDP` banner — `blast → drop` runs a **clean, steady
5.0M pps** end to end, lossless (`nic=0 app=0` on the receiver). That was the
number on this instance type in our testing.

At that point the ceiling is the instance, not the library: AWS's Nitro network
layer **polices packets-per-second**, so past the instance's allowance (~5M pps
on `c7gn.xlarge`) the `pps_allowance_exceeded` counter in `ethtool -S ens5`
climbs and the rate flat-lines there regardless of queues or cores. Bigger
instances raise the allowance.

## Examples

| Example | Shows |
|---------|-------|
| [`examples/helloworld`](examples/helloworld) | the simplest program, `Open` with an ICMP filter, log `Info`, print pings, periodic `Stats` |
| [`examples/drop`](examples/drop) | UDP sink that discards everything, minimal per-packet work, for measuring raw receive pps |
| [`examples/blast`](examples/blast) | UDP packet generator, builds frames in the UMEM and transmits at line rate, the sender to point at `drop` |
| [`examples/l2fwd`](examples/l2fwd) | the low-level API (`NewSocket`/`NewProgram`), reflect frames, per-socket `Stats` |
| [`examples/multiqueue`](examples/multiqueue) | `Open` across all queues, `Info` plus aggregate `Stats` |
| [`examples/udpreflector`](examples/udpreflector) | `Open` plus a UDP-port filter, wire-speed UDP echo with `Info`/`Stats` |
| [`examples/dns`](examples/dns) | a real scenario, a UDP/53 forwarding DNS resolver: AF_XDP client path, `miekg/dns` upstream to 8.8.8.8, async worker pool |

```
go build -o drop ./examples/drop
sudo ./drop -iface eth0 -port 9999
```

The `dns` example is its own Go module (so only it pulls in `github.com/miekg/dns`
and the core library stays dependency-minimal). Build it from its directory:

```
cd examples/dns && go mod tidy && go build .
sudo ./dns -iface eth0 -upstream 8.8.8.8:53
```

## Concurrency

A `Socket` is safe for **one receive goroutine concurrent with one transmit
goroutine, lock-free**. Within a direction it is single-threaded. If multiple
goroutines transmit on one socket, serialize the tx-side calls (`Alloc`,
`Transmit`, `Complete`) with your own mutex; the rx side still needs none. Or give
each producer its own queue. The receive side is single-consumer too.

A common shape is one goroutine per queue handling both directions for that queue,
as in the examples.

## Introspection: `Info` and `Stats`

`Fleet.Info()` reports how the fleet is actually running, handy to log at startup,
and `Fleet.Stats()` aggregates per-queue counters so you do not have to track them
yourself. Both have `String` methods.

```go
info, _ := fleet.Info()
log.Printf("started: %s", info)
// started: eth0: 8 queues, zero-copy, native XDP, 4096x2048B frames, driver ena, filter udp/4789

s, _ := fleet.Stats() // e.g. once a second
log.Print(s)
// rx=1530244 tx=0 packets, 19 pkt/poll, rx_drops=12
```

`Info` exposes the interface, NIC driver, queue count, frame size and count, the
XDP attach mode (native, generic, or hardware, read back from the kernel),
whether zero copy was actually granted (read from each socket's `XDP_OPTIONS`, not
just what was requested), and the applied **filter** as a readable summary
(`udp/53`, `udp/4789 | icmp-echo`, or `all` when nothing is filtered).

`Stats` sums received and transmitted packet counts (straight from the rings, no
per-packet bookkeeping in your loop) and the kernel's drop and error counters
(`rx_dropped`, `rx_ring_full`, invalid descriptors), with a `PerQueue` breakdown
when you need to find a hot or dropping queue. All counters are cumulative, so
sample twice and subtract for a rate. Byte counts are not included, the kernel
does not track them, so sum frame lengths in your loop if you need them.

### Syscall counters

Three counters expose what the library is doing with syscalls, which is usually
what you want when a loop is slower than expected:

| field | meaning |
| --- | --- |
| `Polls` | blocking `poll(2)` calls on the receive side |
| `Kicks` | `sendto(2)` kicks issued on the transmit side |
| `KicksSuppressed` | transmit kicks skipped because need-wakeup showed the driver awake |

`Stats.PacketsPerPoll()` divides `Received` by `Polls`: how many packets each
receive syscall paid for, i.e. how well your loop batches. A `drop` sink at
12 Mpps over 12 zero-copy ixgbe queues measures about 20 packets per poll; a
value near 1 means a syscall per packet, usually because the loop drains less
per wakeup than is waiting. `KicksSuppressed` climbing on a zero-copy link means
[need-wakeup](#need-wakeup) is doing its job.

```go
s, _ := xsk.Stats()
log.Printf("%.0f pkt/poll, %d polls, %d kicks (%d suppressed)",
    s.PacketsPerPoll(), s.Polls, s.Kicks, s.KicksSuppressed)
```

[`examples/drop`](examples/drop) prints `polls/s` and `pkt/poll` on its
per-second line — that is where these are easiest to see against real traffic.

## Cleanup and lifecycle

Call `fleet.Close()` (or `program.Detach`) when you are done. It removes the XDP
program from the interface and frees the BPF maps. Wire it up for both normal exit
and signals:

```go
fleet, _ := afxdp.Open("eth0", afxdp.WithUDPPorts(7000))
defer fleet.Close()

sig := make(chan os.Signal, 1)
signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
<-sig // then return, so the deferred Close runs
```

Crash safety: `Open`/`Attach` attach the program through a **BPF link**, which the
kernel auto-detaches when the process exits, even on a panic or `kill -9` (Linux
5.9+). On older kernels it falls back to the legacy netlink attach, which survives
a crash: the program stays bound to the interface, and since the sockets are gone
it drops matching traffic until removed. Recover a leftover program with
`sudo ip link set dev eth0 xdp off`. `Open` also clears any program already
attached before attaching its own, so a restart after an unclean exit just works.

## Terminology

AF_XDP has its own vocabulary; a quick glossary so the code reads clearly.

**AF_XDP** is the Linux socket family that delivers packets from a NIC driver
straight to userspace, skipping the kernel network stack. An **XSK** ("XDP
socket") is a single AF_XDP socket bound to one NIC receive queue; `xsk` is the
conventional variable name for one (from the kernel and libbpf code), and here an
XSK is the [`Socket`](socket.go) type. The **UMEM** is the region of memory shared
with the kernel that holds packet buffers, called *frames*. The **rings** are the
four single-producer/single-consumer queues between you and the kernel: *fill* and
*rx* on the receive side, *tx* and *completion* on the transmit side, and the
library drives them for you. A **Fleet** (this library's own term, not standard
AF_XDP) is a set of XSKs, one per receive queue, bound together under one XDP
program so you capture every queue at once.

## Under the hood

This is a fork of [`asavie/xdp`](https://github.com/asavie/xdp). It keeps that
project's proven UMEM and ring setup and changes two things that matter in
production.

**Independent rx/tx frame pools.** The upstream library kept a single free-frame
list shared by both directions. A receive goroutine refilling the fill ring while
a transmit goroutine sent packets could be handed the *same* UMEM frame, so a
frame got overwritten while the NIC was still DMA-ing it, corrupting packets on
the wire. The failure is silent: every local counter reads clean and you only see
it as drops at the peer (and, under WireGuard, a TCP retransmit collapse). It hits
hardest on weak-memory-model CPUs like ARM/Graviton. This fork splits the UMEM
into a disjoint receive pool and transmit pool, each owned by one direction, so
there is no shared mutable state on the data path, hence the lock-free one-rx plus
one-tx guarantee above. The ring indices are also accessed with acquire/release
atomics, as the protocol requires, so it is correct on weak-memory CPUs too. (It
also replaces an O(N) free-frame scan with an O(1) pool.)

**All queues, easily, with optional filtering.** Real NICs spread received traffic
across several rx queues (RSS); a socket bound to queue 0 sees only its slice.
`Open` binds one socket to every queue (or a subset with `WithQueues`) under a
single XDP program, and `WithFilter` controls which packets that program redirects
versus passes to the kernel, without you hand-writing per-queue maps or eBPF.

If you need the low-level pieces, `NewProgram`, `NewSocket`, and `Program.Attach`
/ `Register` are exported too; `Open` is just the convenient assembly of them.

## Requirements

AF_XDP needs `CAP_NET_RAW` (or root) and enough locked memory for the BPF maps and
UMEM (raise `RLIMIT_MEMLOCK`, e.g. `ulimit -l`). `Open` picks native zero copy
when the driver supports it and otherwise falls back automatically, so you do not
have to, and `Fleet.Info()` shows what you got. On AWS ENA, zero copy additionally
needs page-sized frames (Open defaults `FrameSize` to 4096 there automatically),
halved channels, and a non-jumbo MTU (the driver caps XDP MTU at 3502, so e.g.
`ethtool -L ens5 combined 2 && ip link set ens5 mtu 1500`) — see the AWS EC2 / ENA
section.

## Credits and license

Forked from [`asavie/xdp`](https://github.com/asavie/xdp) (BSD-3-Clause); the
UMEM/ring mmap and bind logic and the embedded XDP redirect program derive from
that project. The descriptor-pool, concurrency, multi-queue, and filter layers are
new work here. BSD-3-Clause, see [LICENSE](LICENSE).
