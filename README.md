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
    xsk.SendBatch(packets) // returns how many were queued this call
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

Each match is compiled to eBPF instructions with
[`github.com/cilium/ebpf/asm`](https://pkg.go.dev/github.com/cilium/ebpf/asm) into
a single XDP program, loaded and checked by the kernel verifier (the test suite
loads every builder and a composite to prove they verify).

A few things to know. Matches combine with OR, a packet is redirected if it
matches any of them. The one built-in AND is `MatchFlow`, which requires a src
CIDR and a dst CIDR together; arbitrary AND across the other builders is not
expressible as a single filter. The port, proto, and ICMP matchers
are IPv4 only and assume no VLAN tag and no IP options, the common case; the IP
(CIDR) matchers handle both IPv4 and IPv6 and read fixed offsets, so they are not
bothered by IP options or IPv6 extension headers. For classification beyond these
builders, redirect everything and classify in your receive loop.

## Transmit

The easy way is `SendBatch` (copy your buffers in) or `SendFunc` (fill each frame
in place, no copy, ideal for a generator that varies a field per packet). Both
handle all the ring bookkeeping, so you just call them in a loop.

```go
// SendFunc fills each frame in place and returns the packet length.
for {
    xsk.SendFunc(256, func(i int, frame []byte) int {
        n := copy(frame, template)
        // offset 34 is the UDP source port (eth 14 + ip 20); vary it per packet
        binary.BigEndian.PutUint16(frame[34:], srcPort)
        srcPort++
        return n
    })
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

## AWS EC2 / ENA

The `ena` driver (EC2, including the "network optimized" `*n`/`*gn` instances)
supports native XDP, but only under two conditions — miss either and `Open`
silently falls back to **generic** XDP, which works but drops packets on the
floor under load without any counter showing it. `Fleet.Info()` tells you which
mode you got; if it says `generic` on ENA, fix these two things:

1. **Free up queues for XDP.** Native XDP needs a dedicated transmit ring per
   channel, carved out of the same fixed hardware queue budget as your normal
   channels. ENA refuses native attach unless channels are **≤ half** the
   maximum. EC2 gives you roughly one queue per vCPU, so on a 4-vCPU instance
   with 4 channels you must halve it:
   ```
   ethtool -L ens5 combined 2
   ```
   (This is not something the library can avoid — the kernel XDP API has no way
   to declare "this program never transmits", so the driver reserves TX rings
   regardless. go-afxdp only ever redirects or passes, never `XDP_TX`, but ENA
   still requires the headroom.)

2. **Lower the MTU.** Base XDP hands the program one contiguous, page-sized
   (4 KB) buffer per packet, so a 9001-byte jumbo frame doesn't fit and ENA
   rejects the attach. Set the MTU under ~3.5 KB:
   ```
   ip link set dev ens5 mtu 3000
   ```
   (EC2 defaults to jumbo 9001. This is the driver's single-buffer XDP limit,
   not a library choice; ENA has not yet implemented XDP multi-buffer.)

**Zero copy** on ENA additionally needs page-sized (4096-byte) UMEM frames — with
the default 2048 the bind silently drops to native *copy* mode. Open handles this
for you: when it sees the `ena` driver it defaults `FrameSize` to 4096, so with
the two settings above the banner reads `zero-copy, native XDP` with no code
change. (Pass `WithFrameSize` yourself only to override that. It costs twice the
UMEM per queue, which is why 4096 is an ena-only default, not the global one.)

Both `ethtool`/`ip` settings are per-boot; re-apply after a reboot. They are NIC
config, so set them yourself rather than have the library reconfigure your
interface underneath you. (The frame-size default is the one thing the library
*can* safely pick for you, since it only changes its own UMEM, not your NIC.)

Measured on two `c7gn.xlarge` (4 vCPU, 6.1 kernel, `blast` → `drop`, 64-byte
frames), showing why the mode matters:

| Receiver mode | Result |
|---------------|--------|
| generic XDP (default) | ~3.1M rx pps — silently loses ~25% of a 4M pps sender |
| native XDP (queues + MTU) | lossless, rx == tx, `nic=0 app=0` |
| native + zero copy (auto 4096 frames) | 5.0M pps flat |

At that point the ceiling is the instance, not the library: transmit is
CPU-bound in ENA's copy path (there is no zero-copy *acceleration* of small-frame
TX on ENA), and AWS's Nitro network layer **polices packets-per-second** — the
`pps_allowance_exceeded` counter in `ethtool -S ens5` climbs once you push past
the instance's allowance (~5M pps here). Bigger instances raise both limits.

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
// rx=1530244 tx=0 packets, rx_drops=12
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
