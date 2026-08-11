# Multi-buffer (jumbo frames) on AWS ENA — measured

Why this exists: EC2 ships ENA interfaces at **MTU 9001**, and base XDP hands the
program one page-sized buffer per packet. ENA therefore refuses a native XDP
attach above 3502 bytes, go-afxdp silently falls back to **generic** XDP, and the
user loses roughly a quarter of their traffic with no counter showing it. The
documented workaround was `ip link set dev ens5 mtu 3000` — a box-wide change to
a production NIC.

Multi-buffer (`XDP_USE_SG` + `BPF_F_XDP_HAS_FRAGS`) is the kernel feature that
removes the constraint. This is what we measured.

## Test rig

Two `c7gn.xlarge` (aarch64 Graviton, 4 vCPU), Amazon Linux 2023, kernel
**6.18.38-76.139**, ENA driver **2.17.2g**, `ens5` at MTU 9001 with combined
channels 4/4, same subnet, 0.24 ms apart. Traffic over private IPs.

## 1. The negative case reproduces exactly

At stock EC2 configuration, `Open` returns a healthy-looking fleet:

```
OPEN-OK  ens5: 4 queues, copy, generic XDP, 8192x4096B frames, driver ena, filter all
  xdpmode=generic zerocopy=false
```

No error, no warning. Forcing native fails:

```
OPEN-FAILED mode=native  native attach: create link: invalid argument
```

with the reason in dmesg:

```
ena ens5: Failed to set xdp program, the current MTU (9001) is larger than
the maximum allowed MTU (3502) while xdp is on
```

## 2. MTU is the only blocker — the channel advice is stale

Isolating the two documented ENA conditions:

| MTU | channels | `Open` result | forced native |
|---|---|---|---|
| 9001 | 4/4 | generic (silent) | FAIL |
| 9001 | 2/4 | generic (silent) | FAIL |
| 3000 | 4/4 | **native zero-copy** | OK |
| 3000 | 2/4 | **native zero-copy** | OK |

Full channels work fine on ENA 2.17.2g, for both receive and transmit. The
README's `ethtool -L ens5 combined 2` step is not needed on this driver.

The requirement was real, and the driver says when it went away: ENA 2.17.0
lists "Full queues utilization in XDP" as a new feature, and the current source
has no XDP queue-count check left (`ena_xdp_legal_queue_count` and the
queue-count rejection path are both gone). The README now scopes the step to
ENA older than 2.17.0 rather than dropping it, since older AMIs still ship
those versions.

## 3. Root cause: a stale compat probe in the ENA driver

`BPF_F_XDP_HAS_FRAGS` alone did **not** lift the cap. Isolated with a minimal
two-instruction `XDP_PASS` program so nothing in our filter could be implicated:

| | MTU 9001 | MTU 3000 |
|---|---|---|
| native, no frags | FAIL | OK |
| native, **HAS_FRAGS** | **FAIL** | OK |

The driver gates the check correctly in source (`ena_xdp.c:369`):

```c
static int ena_get_max_xdp_mtu(struct ena_adapter *adapter, struct bpf_prog *prog)
{
#ifndef ENA_XDP_MB_SUPPORT
	return prog ? ENA_XDP_MAX_SINGLE_FRAME_SIZE : adapter->max_mtu;
#else
	if (!prog || prog->aux->xdp_has_frags)
		return adapter->max_mtu;
	return ENA_XDP_MAX_SINGLE_FRAME_SIZE;
#endif
}
```

but `ENA_XDP_MB_SUPPORT` is never defined on this kernel. It depends on
`ENA_HAVE_XDP_MB_DEPS`, a compile probe (`config/test_defs.sh:173`) that tests
for `xdp_update_skb_shared_info` — a function upstream **renamed** to
`xdp_update_skb_frags_info`. The compiler says so directly:

```
error: implicit declaration of function 'xdp_update_skb_shared_info';
       did you mean 'xdp_update_skb_frags_info'?
```

The driver's own body already uses the new name (`kcompat.h:1087` aliases it
back for older kernels). Only the probe was left behind, so multi-buffer is
silently compiled out on modern kernels.

**Patching that one line** and rebuilding flips `ENA_HAVE_XDP_MB_DEPS 1`, and:

| at MTU 9001 | stock driver | patched driver |
|---|---|---|
| native, no frags | FAIL | FAIL *(correct)* |
| native, **HAS_FRAGS** | **FAIL** | **ATTACH-OK** |

## 4. Multi-buffer works, but never with zero-copy on ENA

`ens5` advertises `xdp-features = 0x6f`
(`basic|redirect|ndo-xmit|xsk-zerocopy|rx-sg|ndo-xmit-sg`) but
**`xdp-zc-max-segs = 1`**, both before and after the patch. Per the kernel docs
that means multi-buffer zero-copy is unsupported. Confirmed at bind:

```
plain,  zerocopy    OK      zerocopy=true
USE_SG, zerocopy    FAILED  operation not supported
USE_SG, native      OK      zerocopy=false   <- drops to copy
```

So on ENA the choice is **jumbo or zero-copy, never both**:

| config | MTU step? | mode |
|---|---|---|
| stock today | none | **generic** (~25% loss under load) |
| lower the MTU | yes | native **zero-copy** |
| `WithMultiBuffer` + patched driver | **none** | native **copy** |

Native copy is far better than generic, but it is not better than lowering the
MTU. `WithMultiBuffer` is therefore opt-in, and its doc comment says so.

## 5. End-to-end: jumbo receive

Receiver on the patched box at MTU 9001, `WithMultiBuffer`, filter `icmp-echo`;
sender is the peer's **kernel** stack so our transmit path is not in the loop.

```
multibuffer=true -> ens5: 4 queues, copy, native XDP, 8192x4096B frames, driver ena
captured 15 packets (45 frames), largest reassembled packet 8942 bytes
  15 packet(s) spanned 3 frame(s)
```

100% ping loss at the sender is the proof of capture: the packets were
redirected to the socket, so the kernel never replied.

Mixed sizes, one capture, fragment counts exactly as predicted:

| payload | on-wire | frames | why |
|---|---|---|---|
| 100 B | 142 | 1 | under the 3502 single-frame limit |
| 1400 B | 1442 | 1 | under the limit |
| 4000 B | 4042 | 2 | over 3502 (headroom + `skb_shared_info` consume part of the 4096 frame) |
| 8900 B | 8942 | 3 | — |

Single-frame packets are unaffected: a small-packet-only run captured 10 of 10,
each one fragment.

## 6. End-to-end: jumbo transmit

`SendBatch` splitting an 8942-byte payload across three frames with
`XDP_PKT_CONTD`, received by the peer's kernel:

```
17:50:12 IP 172.31.31.102.12345 > 172.31.16.177.4242: UDP, length 1358   x3
17:50:14 IP 172.31.31.102.12345 > 172.31.16.177.4242: UDP, length 8900   x3
```

All frames returned on the completion ring (9/9 for the chained run).

## Reproduce

```bash
# capability gate — needs rx-sg set, and zc-max-segs >= 2 for zero-copy jumbo
go run ./cmd/xdpfeat ens5

# patch the ENA driver probe (until Amazon ships the fix)
git clone --depth 1 https://github.com/amzn/amzn-drivers
cd amzn-drivers/kernel/linux/ena
sed -i 's/xdp_update_skb_shared_info(NULL, 0, 0, 0, false);/xdp_update_skb_frags_info(NULL, 0, 0, 0, 0);/' \
    config/test_defs.sh
make && modprobe -r ena && insmod ./ena.ko   # NIC drops briefly; reboot restores stock
```

## Open items

- The driver fix belongs upstream in `amzn-drivers`; until it ships, stock EC2
  AMIs still fall back to generic XDP at MTU 9001.
- `xdp-zc-max-segs` is 1 on ENA. If a future device reports >= 2, re-run §4 —
  jumbo *and* zero-copy would then be possible and `WithMultiBuffer` would stop
  being a trade-off.
