# Does wireblast work on a plain EC2 instance?

Short answer: **yes, it works, and it is lossless.** But it leaves zero-copy on
the floor on ENA, for a reason that is a one-line fix in wireblast.

## Setup

Two `c7gn.xlarge` (4 vCPU aarch64 Graviton, AL2023, kernel 6.18.38), rebooted to
the **stock in-tree ENA driver** 2.17.2g, **MTU 1500**, default **4/4 channels**.
No driver patch, no `ethtool -L`, nothing special. Traffic between private IPs
172.31.16.177 (sender) and 172.31.31.102 (receiver).

wireblast **v0.2.2**, `wireblast_linux_arm64.tar.gz`, sha256 verified against
the published `checksums.txt`. Statically linked, dropped in and run.

It pins **go-afxdp v0.7.0**, which is exactly commit `1289d02`, the multi-buffer
merge from earlier today.

## It works

Fixed rate, 64-byte UDP, 64 flows:

```
tx: 60 M packets, 2 Mpps, L1 1.34 Gbit/s, avg frame 64B
rx: 60 M packets, 2 Mpps, L1 1.34 Gbit/s, avg frame 64B
```

Exact match, zero loss.

Unlimited rate (`--pps max`):

```
tx: 143.71 M packets, 4.79 Mpps avg (peak 4.97), L1 3.22 Gbit/s
rx: 143.53 M packets, drops 3217
```

**0.13% loss at 4.79 Mpps.** That is right at the instance's Nitro pps
allowance, so the ceiling is the instance and not the tool.

SSH survived on both boxes. The XDP attach dropped carrier for 0.8s, which
wireblast reported and rode out. `--rx-mode udp-port` only claims UDP/9000, so
the management session was never at risk.

The startup safety output is genuinely good: it warned that `ens5` owns the
default route, that receive mode takes traffic from the kernel, and that the SSH
session runs over the interface under test, naming the actual client IP.

## But it does not get zero-copy, and go-afxdp does

Same boxes, same MTU 1500, same 64-byte UDP, minutes apart:

| | mode reported | rate |
|---|---|---|
| go-afxdp `blast`/`drop` | **zero-copy**, native XDP | 5.00 Mpps, 0.22% loss |
| wireblast | **copy**, native XDP | 4.79 Mpps, 0.13% loss |

Both ends of the wireblast run report `copy`, sender and receiver.

### Cause

wireblast sizes its UMEM frames from the packet size. The binary contains
`github.com/atoonk/wireblast/internal/dataplane.frameSizeFor`. Sweeping packet
size against the reported mode:

| MTU | packet size | mode |
|---|---|---|
| 1500 | 64 B | copy |
| 1500 | 1400 B | copy |
| 3000 | 64 B | copy |
| 3000 | 1400 B | copy |
| 3000 | **3000 B** | **zero-copy** |

Zero-copy only appears once the packet is large enough to push the chosen frame
size to 4096. That is exactly the ENA constraint go-afxdp's own README documents:

> **Zero copy** on ENA additionally needs page-sized (4096-byte) UMEM frames —
> with the default 2048 the bind silently drops to native *copy* mode.

go-afxdp handles this automatically, but **only when the caller leaves
`FrameSize` at zero** (`fleet.go:113`):

```go
if cfg.opts.FrameSize == 0 && cfg.mode != modeGeneric && interfaceDriver(iface) == "ena" {
    base.FrameSize = 4096
}
```

By computing its own frame size, wireblast opts out of that default and loses
zero-copy on every ENA instance for any packet under ~4 KB, which is essentially
all traffic anyone benchmarks.

### Suggested fix, in wireblast

Either leave `FrameSize` unset so go-afxdp's ENA default applies, or floor the
computed size at 4096 when the driver is `ena`. The driver name is already
available from `Fleet.Info().Driver`.

Cost of not fixing it, from measurements taken on these same boxes earlier
today: copy mode costs about **1.25× CPU per packet at 64 bytes** and **1.76× at
1400 bytes**, plus roughly 4% throughput here.

## Incidentally: wireblast's ENA docs are stale in the same way go-afxdp's were

`concepts/hardware` says:

> ENA exposes one combined queue by default and caps XDP MTU at 3502.

and recommends `sudo ethtool -L ens5 combined 2`.

Neither half held on this instance. A stock `c7gn.xlarge` came up with **4
combined queues**, not one, and native XDP with zero-copy attached at **4/4
channels** with no `ethtool -L` at all. The channel requirement was removed in
ENA 2.17.0 ("full queues utilization in XDP"); go-afxdp's README was corrected
for this earlier today and wireblast's page needs the same treatment.

## Verdict

Someone can download the release binary onto an ordinary EC2 instance and it
works: native XDP, lossless, right up to the instance's pps allowance, with no
tuning. The gap is that it silently runs in copy mode where zero-copy is
available, which costs CPU headroom and a few percent of throughput.
