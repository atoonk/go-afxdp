# Jumbo frames on AWS ENA

EC2 ships ENA interfaces at **MTU 9001**, but the ENA driver refuses a native
XDP attach above 3502 bytes, so go-afxdp silently falls back to generic XDP,
which drops packets under load with no counter showing it. The usual advice is
to lower the MTU. This directory is the alternative: a one line driver patch
that makes XDP work at the full 9001 MTU, so `WithMultiBuffer()` gives you real
jumbo frames.

## Read this first

| | |
|---|---|
| Jumbo frames (9001 MTU) over AF_XDP | yes |
| Native XDP instead of the generic fallback | yes |
| **Zero-copy** together with jumbo | **no** |

ENA reports `xdp-zc-max-segs = 1`, which means the kernel refuses an
`XDP_USE_SG` bind in zero-copy mode. With this patch you get **native copy**
mode at MTU 9001. Native copy is much better than the generic fallback, but it
is *slower than lowering the MTU and using zero-copy*. So:

- **You need jumbo frames.** Apply this patch and use `WithMultiBuffer()`.
- **You just want maximum pps at normal packet sizes.** Do not apply this. Run
  `ip link set dev ens5 mtu 3000` and leave `WithMultiBuffer()` off. That gets
  you native zero-copy, which is faster.

Jumbo *and* zero-copy together additionally needs
[amzn-drivers#378](https://github.com/amzn/amzn-drivers/pull/378), which as of
this writing does not build against current kernels.

Everything below was run start to finish on a stock `c7gn.xlarge` running
Amazon Linux 2023, kernel `6.18.38-76.139`, ENA `2.17.2g`. Run it as root.

## Step 1: install what you need to build a kernel module

A fresh AL2023 instance has none of this. The kernel headers package is named
after the kernel *series* (`kernel6.18-devel`, not `kernel-devel`) and must
match your **running** kernel exactly, so derive the name rather than guessing:

```bash
dnf install -y git gcc make \
  "$(rpm -qf /boot/config-$(uname -r) --qf '%{NAME}')-devel-$(uname -r | sed 's/\.[^.]*$//')"
```

Check it worked. This must print a real directory, not an error:

```bash
ls -d /lib/modules/$(uname -r)/build/
```

## Step 2: get the driver source and patch it

```bash
cd /root
git clone --depth 1 https://github.com/amzn/amzn-drivers.git
cd amzn-drivers
git apply /path/to/go-afxdp/contrib/ena-jumbo/0001-ena-fix-xdp-multi-buffer-probe.patch
```

If you do not have a go-afxdp checkout handy, fetch the patch directly:

```bash
curl -fsSL -o /tmp/ena-jumbo.patch \
  https://raw.githubusercontent.com/atoonk/go-afxdp/main/contrib/ena-jumbo/0001-ena-fix-xdp-multi-buffer-probe.patch
git apply /tmp/ena-jumbo.patch
```

Confirm it applied. This must show one file changed, one deletion:

```bash
git diff --stat
#  kernel/linux/ena/config/test_defs.sh | 1 -
#  1 file changed, 1 deletion(-)
```

## Step 3: build

```bash
cd kernel/linux/ena
make -j"$(nproc)"
```

**Do not skip this check.** It is the whole point of the patch, and the build
succeeds either way, so this is the only way to know it worked:

```bash
grep ENA_HAVE_XDP_MB_DEPS config.h
# #define ENA_HAVE_XDP_MB_DEPS 1
```

If that prints nothing, the patch did not take effect and loading the module
will change nothing. Go back to step 2.

## Step 4: load it

**This briefly removes your only network interface.** Your SSH session will
drop and come back after roughly ten seconds. The block below detects your
interface and gateway, runs the swap detached so it survives the disconnect,
and puts the stock driver back automatically if the box ends up unreachable.
It also schedules a reboot as a second safety net.

Copy the whole thing at once:

```bash
cd /root/amzn-drivers/kernel/linux/ena

IFACE=$(ip -o -4 route show default | awk '{print $5; exit}')
GW=$(ip -o -4 route show default | awk '{print $3; exit}')
echo "interface=$IFACE gateway=$GW"

shutdown -r +5 "ena module swap safety net"

nohup setsid bash -c "
  sleep 3
  modprobe -r ena
  insmod $PWD/ena.ko
  sleep 8
  ip link set dev $IFACE up
  sleep 6
  ping -c2 -W2 $GW >/dev/null 2>&1 || { rmmod ena; modprobe ena; sleep 8; ip link set dev $IFACE up; }
" >/dev/null 2>&1 < /dev/null &
```

Wait about fifteen seconds, reconnect, then **cancel the safety reboot**:

```bash
shutdown -c
```

If you cannot reconnect, do nothing. The reboot fires within five minutes and
brings the box back on the stock driver.

## Step 5: verify

Save this as `main.go` in an empty directory and run it as root:

```go
package main

import (
	"log"
	"sync"
	"time"

	xdp "github.com/atoonk/go-afxdp"
)

func main() {
	fleet, err := xdp.Open("ens5",
		xdp.WithFilter(xdp.MatchICMPEcho()),
		xdp.WithMultiBuffer(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer fleet.Close()

	info, _ := fleet.Info()
	log.Print(info)
	if info.XDPMode != "native" {
		log.Fatalf("got %s XDP, wanted native: the driver patch is not in effect", info.XDPMode)
	}

	// One goroutine per queue. The NIC spreads packets across all of them by
	// RSS hash, so reading only Sockets()[0] will usually see nothing at all:
	// the XDP program still redirects the packets, they just pile up unread on
	// whichever queue they landed on.
	var wg sync.WaitGroup
	deadline := time.Now().Add(30 * time.Second)
	for i, xsk := range fleet.Sockets() {
		wg.Add(1)
		go func(q int, xsk *xdp.Socket) {
			defer wg.Done()
			buf := make([]byte, 65536)
			for time.Now().Before(deadline) {
				xsk.Fill(xsk.FreeRxFrames())
				if _, err := xsk.Poll(200 * time.Millisecond); err != nil {
					return
				}
				pkts := xsk.ReceivePackets(64)
				for _, p := range pkts {
					n := xsk.CopyOut(p, buf)
					log.Printf("queue %d: got a %d byte packet spanning %d frame(s)", q, n, len(p))
				}
				xsk.RecyclePackets(pkts)
			}
		}(i, xsk)
	}
	wg.Wait()
}
```

```bash
go mod init verify && go get github.com/atoonk/go-afxdp && go build -o verify . && ./verify
```

Build the binary rather than using `go run` directly: the first `go run` spends
several seconds compiling, and it is easy to send your test traffic before the
socket is actually bound.

While it runs, ping this instance from another host with a jumbo payload:

```bash
ping -M do -s 8900 <this-instance-private-ip>
```

Expected output:

```
ens5: 4 queues, copy, native XDP, 8192x4096B frames, driver ena, filter icmp-echo, ...
queue 2: got a 8942 byte packet spanning 3 frame(s)
queue 2: got a 8942 byte packet spanning 3 frame(s)
queue 2: got a 8942 byte packet spanning 3 frame(s)
```

All of one ping flow lands on a single queue, because RSS hashes on the flow.
Which queue it picks is not predictable, and that is exactly why the program
above reads all of them.

Three things to look for:

- **`native XDP`**, not `generic XDP`. Generic means the attach was still
  refused; check `dmesg` for the 3502 message and re-check step 3.
- **`spanning 3 frame(s)`**. That is the jumbo packet arriving as a chain.
- **`copy` rather than `zero-copy` is expected here** and is not a failure. See
  the table at the top.

The ping will report 100% packet loss. That is correct: the XDP program
redirected the packets to your socket, so the kernel never replied.

## Undoing it

The patched module is **not** installed to `/lib/modules`, so:

```bash
reboot
```

restores the stock driver. That also means the patch does not survive reboots.
For a persistent install, build it through DKMS instead of `insmod`.

## Why the patch is needed

`ENA_HAVE_XDP_MB_DEPS` is a compile probe that tests for
`xdp_update_skb_shared_info()`. Upstream Linux renamed that function to
`xdp_update_skb_frags_info()`, so on current kernels the probe fails,
`ENA_XDP_MB_SUPPORT` is never defined, and `ena_get_max_xdp_mtu()` applies the
3502 byte single buffer cap unconditionally, ignoring `BPF_F_XDP_HAS_FRAGS`.

The driver's own code already uses the new name. `kcompat.h` aliases it back for
older kernels, and the probe for *that* macro further down the same file already
tests the new name. Only this one aggregate probe was missed, so the fix removes
the stale call rather than renaming it. Renaming would break older kernels that
carry only the old symbol.

Isolated with a minimal two instruction `XDP_PASS` program, so nothing in
go-afxdp's own filter could be implicated. At MTU 9001 a native attach fails
both with and without `BPF_F_XDP_HAS_FRAGS` on the stock driver, and succeeds
with the flag once the probe is fixed. At MTU 3000 both attach either way.

## Status

This is a workaround for a bug in a third party driver, not part of go-afxdp.
Once Amazon ships the fix, drop the patch and this directory goes away.
