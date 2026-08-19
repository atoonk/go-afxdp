// Separate module: github.com/cloudflare/cbpfc requires a newer Go and
// cilium/ebpf than go-afxdp's root module targets, and only this layer needs
// it. Keeping it out means users of the built-in matchers keep the older
// baseline and a smaller dependency set.
module github.com/atoonk/go-afxdp/bpfmatch

go 1.25.0

// RELEASE: this version must be a real parent tag that contains the NewMatch/
// MatchError/MatchPacket API (v0.9.0 is the first). Tag order: parent first,
// then this module as bpfmatch/vX.Y.Z. The replace below covers local dev only
// and is ignored downstream, so a wrong version here breaks `go get`.
require (
	github.com/atoonk/go-afxdp v0.9.0
	github.com/cilium/ebpf v0.22.0
	github.com/cloudflare/cbpfc v0.0.0-20260805072904-7ac485fd93e1
	golang.org/x/net v0.57.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Develop against the checkout; ignored by anyone importing this module.
replace github.com/atoonk/go-afxdp => ../
