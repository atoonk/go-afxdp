// Separate module: expression parsing needs libpcap via cgo, and go-afxdp's
// root module is pure Go. Keeping this out of the root module means
// `go build ./...` and `go test ./...` there never require libpcap.
module github.com/atoonk/go-afxdp/pcapfilter

go 1.25.0

// RELEASE: both sibling versions must be real tags — the replaces below are
// ignored downstream. Tag order: parent v0.9.0, then bpfmatch/v0.9.0, then
// this module as pcapfilter/vX.Y.Z (it depends on both).
require (
	github.com/atoonk/go-afxdp v0.9.0
	github.com/atoonk/go-afxdp/bpfmatch v0.9.0
	github.com/cilium/ebpf v0.22.0
	github.com/gopacket/gopacket v1.3.1
	golang.org/x/net v0.57.0
)

require (
	github.com/cloudflare/cbpfc v0.0.0-20260805072904-7ac485fd93e1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Develop against the checkout; ignored by anyone importing this module.
replace (
	github.com/atoonk/go-afxdp => ../
	github.com/atoonk/go-afxdp/bpfmatch => ../bpfmatch
)
