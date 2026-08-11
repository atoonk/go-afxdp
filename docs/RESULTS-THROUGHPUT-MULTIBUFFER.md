# Throughput: what multi-buffer and copy mode actually cost on EC2

Clean-room run on two freshly rebooted `c7gn.xlarge` (4 vCPU Graviton, AL2023,
kernel 6.18.38, ena 2.17.2g), `examples/blast` to `examples/drop` over the
private subnet, both boxes patched by following `contrib/ena-jumbo/README.md`
verbatim. Traffic 172.31.16.177 to 172.31.31.102.

The examples were given a local, uncommitted `-multibuffer` flag so they could
reach `WithMultiBuffer()`. `drop`'s receive loop was deliberately left on
`Receive`/`Recycle` so every cell runs identical rx code; at 64 and 1400 bytes
each packet is one frame, so that is correct throughout.

## Headline

**At 64 bytes all three native modes hit the same ~5 Mpps wall, because the wall
is the instance, not the datapath.** The copy penalty is invisible in throughput
and only shows up in CPU.

| size | MTU | mode | rx pps | CPU/packet | cores busy |
|---|---|---|---|---|---|
| 64 B | 3000 | zero-copy | **5.00 M** | 0.280 us | 34.9% |
| 64 B | 3000 | copy | 4.96 M | 0.349 us | 43.9% |
| 64 B | 9001 | copy | 4.29 M | 0.375 us | 40.7% |
| 1400 B | 3000 | zero-copy | 1.20 M | 0.325 us | 9.8% |
| 1400 B | 3000 | copy | 1.30 M | 0.572 us | 18.9% |

CPU is whole-system busy time from `/proc/stat` over a 20 s window in the middle
of the run, not per-process: the copy happens in kernel softirq context, so
process CPU would miss it entirely.

## The copy penalty

Measured at fixed MTU 3000, so the only variable is the datapath:

| packet size | zero-copy | copy | ratio |
|---|---|---|---|
| 64 B | 0.280 us | 0.349 us | **1.25x** |
| 1400 B | 0.325 us | 0.572 us | **1.76x** |

It scales with bytes copied, as expected. At 64 bytes it costs a quarter more
CPU per packet; at 1400 bytes it nearly doubles it.

**Throughput is unaffected in both cases**, because something else binds first:
at 64 B the Nitro pps allowance (~5 M pps), at 1400 B the bandwidth allowance
(~1.2 M pps is about 13.5 Gbit/s). So on this instance size you can turn on
multi-buffer and lose no packets per second at all. You pay in headroom, not in
throughput, and that only matters once the CPU is the binding constraint.

## MTU 9001 costs more than copy mode does

Comparing the two copy-mode rows at 64 B, which differ only in MTU:

- MTU 3000: 4.96 M pps
- MTU 9001: 4.29 M pps

**About 13% fewer packets per second purely from running at the jumbo MTU**,
larger than the copy penalty itself. The driver posts bigger receive buffers at
9001 regardless of actual packet size. Worth knowing: if you enable multi-buffer
but do not actually need jumbo frames, you pay this for nothing.

## Generic XDP is far better than the README claims

Cell 1, stock driver, MTU 9001, no multi-buffer, which is what a user gets today
with no intervention:

- tx 5.00 M pps, rx 4.89 M pps, about **2% loss**
- application ring-full drops present but small
- `pps_allowance_exceeded` moved only 3,684

The README states generic "silently loses ~25% of a 4M pps sender", measured on
a 6.1 kernel. On 6.18 the gap is roughly 2%. **That README figure is stale and
should be re-measured before it is quoted again.**

Generic is still worse: it drops packets where native does not, it cannot do
zero-copy, and it leaves NAPI untuned. But "loses a quarter of your traffic" no
longer describes it.

## Watch out for Nitro burst credits

The first run of the MTU 9001 multi-buffer cell showed 19.2% loss and 225,581
`pps_allowance_exceeded`. Re-running the identical cell after a cooldown gave
0.48% loss and 21,460. The difference was burst credits that had not refilled
after the previous cell had just pushed 5 M pps for 30 seconds.

**Any benchmark on these instances needs a cooldown between runs**, or the first
result after a heavy run is meaningless. All numbers in the tables above were
taken with a 45 s gap.

Related: `drop`'s `nic=` counter reads `rx_missed_errors`, which ENA does not
populate. It reads 0 no matter what. Use `ethtool -S ens5 | grep allowance`
instead, and compare sender pps against receiver pps for ground truth.

## Jumbo still works

At MTU 9001 with the patched driver, mixed ping sizes captured through
`ReceivePackets`:

```
queue 2: got a 8942 byte packet spanning 3 frame(s)   x3
queue 2: got a 4042 byte packet spanning 2 frame(s)   x2
queue 2: got a 142 byte packet spanning 1 frame(s)    x2
```

Every packet accounted for, fragment counts exactly as predicted.

This run also found a bug in `contrib/ena-jumbo/README.md`: its verify snippet
read only `fleet.Sockets()[0]`, and all of one ping flow lands on a single
RSS-chosen queue, so it saw nothing at all while the XDP program was correctly
redirecting. Fixed to read every queue.

## What this means

- **Turning on multi-buffer costs you no throughput on a c7gn.xlarge.** The
  instance's allowances bind well before the datapath does.
- **It does cost CPU headroom**, 1.25x to 1.76x per packet depending on size.
  That matters when you are CPU-bound, which on this instance size you are not.
- **If you do not need jumbo frames, still lower the MTU.** Not for the copy
  penalty, but for the 13% pps cost of the jumbo MTU itself.
- **The 5.0 M pps figure in the README still holds** on 6.18 and ena 2.17.2g,
  reproduced exactly at 5.00 M pps with 0.16% loss.
