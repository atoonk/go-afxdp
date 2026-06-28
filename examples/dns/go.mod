// The dns example has its own module so the core go-afxdp library stays
// dependency-minimal (ebpf, netlink, sys) and only this example pulls in
// github.com/miekg/dns.
//
// Build it from this directory:
//
//	cd examples/dns && go mod tidy && go build .
module github.com/atoonk/go-afxdp/examples/dns

go 1.22

require (
	github.com/atoonk/go-afxdp v0.0.0-00010101000000-000000000000
	github.com/miekg/dns v1.1.58
)

require (
	github.com/cilium/ebpf v0.16.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/mod v0.14.0 // indirect
	golang.org/x/net v0.23.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/tools v0.17.0 // indirect
)

replace github.com/atoonk/go-afxdp => ../..
