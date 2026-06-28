// dns is a small UDP DNS forwarding resolver built on AF_XDP. It answers DNS
// queries sent to this host on UDP/53 by forwarding them to an upstream
// resolver (8.8.8.8 by default, which does the actual recursion) and sending
// the reply straight back to the client.
//
//	go build -o dns ./examples/dns
//	sudo ./dns -iface eth0 -upstream 8.8.8.8:53
//
// Then from another machine on the segment:
//
//	dig @<this-host-ip> example.com
//
// This is a realistic use of AF_XDP: the client-facing fast path runs in
// userspace (so you could add caching, filtering, rewriting, logging, DoH/DoT
// upstreams, ... — things that don't fit in an XDP/eBPF program), while the
// in-kernel XDP filter lifts only UDP/53 to us and leaves all other traffic to
// the normal stack. The upstream query uses an ordinary kernel UDP socket (via
// github.com/miekg/dns); its reply comes back to an ephemeral port (not 53), so
// the XDP filter doesn't grab it — the two paths separate cleanly.
//
// Concurrency: one goroutine receives queries off the AF_XDP socket and feeds a
// pool of workers. Each worker resolves its query upstream (slow, ~ms of RTT)
// and then transmits the reply. Because the library gives each Socket disjoint
// receive and transmit frame pools, the receive goroutine never contends with
// transmit; the only synchronization is a mutex shared by the workers, since
// they are multiple producers on the one transmit ring. The receive loop never
// blocks on upstream I/O.
//
// It parses Ethernet + IPv4 (no options) + UDP. A production resolver would add
// a cache and EDNS handling; the point here is the AF_XDP plumbing.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/atoonk/go-afxdp"
	"github.com/miekg/dns"
)

func main() {
	iface := flag.String("iface", "eth0", "interface to bind")
	upstream := flag.String("upstream", "8.8.8.8:53", "upstream DNS resolver")
	queues := flag.Int("queues", 0, "rx queues to bind (0 = all)")
	workers := flag.Int("workers", 64, "upstream resolver workers per queue")
	verbose := flag.Bool("v", false, "log each query")
	flag.Parse()

	// Lift only UDP/53 into userspace; everything else stays in the kernel.
	// Open auto-selects the XDP mode (native zero-copy where available).
	fleet, err := afxdp.Open(*iface,
		afxdp.WithUDPPorts(53),
		afxdp.WithQueues(*queues),
	)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer fleet.Close()
	if info, err := fleet.Info(); err == nil {
		log.Printf("DNS resolver up (upstream %s, %d workers/queue): %s", *upstream, *workers, info)
	}

	for _, xsk := range fleet.Sockets() {
		go serve(xsk, *upstream, *workers, *verbose)
	}

	// Periodic stats: rx = queries received, tx = answers sent.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			if s, err := fleet.Stats(); err == nil {
				log.Printf("[stats] %s", s)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("stopping")
}

// job carries one client request from the receive loop to a worker: the frame
// header to reverse for the reply, and the raw DNS query payload.
type job struct {
	hdr   [udpPayloadOff]byte
	query []byte
}

// serve runs one queue: a receive loop that never blocks on upstream I/O, plus
// a pool of workers that resolve and transmit. The workers share txMu because
// they are multiple producers on the one transmit ring; the receive loop needs
// no lock (disjoint rx/tx pools).
func serve(xsk *afxdp.Socket, upstream string, workers int, verbose bool) {
	var txMu sync.Mutex
	client := &dns.Client{Timeout: 3 * time.Second}
	jobs := make(chan job, 2048)
	for i := 0; i < workers; i++ {
		go worker(xsk, &txMu, client, upstream, jobs, verbose)
	}

	for {
		xsk.Fill(xsk.NumFreeFillSlots())
		n, err := xsk.Poll(-1)
		if err != nil {
			close(jobs)
			return
		}
		rx := xsk.Receive(n)
		for _, d := range rx {
			frame := xsk.GetFrame(d)
			if len(frame) <= udpPayloadOff {
				continue
			}
			var j job
			copy(j.hdr[:], frame[:udpPayloadOff])
			j.query = append([]byte(nil), frame[udpPayloadOff:]...)
			select {
			case jobs <- j:
			default:
				// Worker pool saturated: drop (the client will retry). A real
				// resolver would size the pool/queue for its load.
			}
		}
		xsk.Recycle(rx)
	}
}

// worker resolves queries upstream and transmits the replies.
func worker(xsk *afxdp.Socket, txMu *sync.Mutex, client *dns.Client, upstream string, jobs <-chan job, verbose bool) {
	for j := range jobs {
		answer, err := resolve(client, upstream, j.query, verbose)
		if err != nil {
			if verbose {
				log.Printf("upstream error: %v", err)
			}
			continue
		}
		if len(answer) == 0 {
			continue
		}
		txMu.Lock()
		xsk.Complete(xsk.NumCompleted()) // reclaim sent frames
		tx := xsk.Alloc(1)
		if len(tx) > 0 {
			out := xsk.GetFrame(tx[0])
			if udpPayloadOff+len(answer) <= len(out) { // fits in one frame
				tx[0].Len = uint32(buildReply(j.hdr[:], answer, out))
				xsk.Transmit(tx[:1])
			}
		}
		txMu.Unlock()
	}
}

// resolve forwards a raw DNS query to the upstream resolver and returns the
// packed response. miekg/dns handles the upstream socket and message framing;
// a *dns.Client is safe for concurrent use (it dials per Exchange).
func resolve(client *dns.Client, upstream string, query []byte, verbose bool) ([]byte, error) {
	var q dns.Msg
	if err := q.Unpack(query); err != nil {
		return nil, err
	}
	if verbose && len(q.Question) > 0 {
		log.Printf("query %s %s", q.Question[0].Name, dns.TypeToString[q.Question[0].Qtype])
	}
	resp, _, err := client.Exchange(&q, upstream)
	if err != nil {
		return nil, err
	}
	return resp.Pack()
}

// Header field offsets for Ethernet(14) + IPv4(20, no options) + UDP(8).
const (
	ethDst        = 0
	ethSrc        = 6
	ipTotalLen    = 16
	ipChecksumOff = 24
	ipSrc         = 26
	ipDst         = 30
	udpSrcPort    = 34
	udpDstPort    = 36
	udpLen        = 38
	udpChecksum   = 40
	udpPayloadOff = 42
)

// buildReply turns a captured request header plus the upstream answer into a
// response frame written into out, returning its length. It reverses the
// addresses at every layer (the answer goes back to whoever asked) and fixes up
// the lengths and the IPv4 header checksum, since the answer is a different size
// than the query. The UDP checksum is set to 0, which is legal for IPv4; if
// your path drops zero-checksum UDP, compute it instead.
func buildReply(reqHdr, answer, out []byte) int {
	total := udpPayloadOff + len(answer)

	copy(out[:udpPayloadOff], reqHdr) // start from the request header

	// Reverse src/dst at each layer (read from the original request header).
	copy(out[ethDst:ethDst+6], reqHdr[ethSrc:ethSrc+6])                 // to client MAC
	copy(out[ethSrc:ethSrc+6], reqHdr[ethDst:ethDst+6])                 // from our MAC
	copy(out[ipSrc:ipSrc+4], reqHdr[ipDst:ipDst+4])                     // from our IP
	copy(out[ipDst:ipDst+4], reqHdr[ipSrc:ipSrc+4])                     // to client IP
	copy(out[udpSrcPort:udpSrcPort+2], reqHdr[udpDstPort:udpDstPort+2]) // from :53
	copy(out[udpDstPort:udpDstPort+2], reqHdr[udpSrcPort:udpSrcPort+2]) // to client port

	binary.BigEndian.PutUint16(out[ipTotalLen:], uint16(20+8+len(answer)))
	binary.BigEndian.PutUint16(out[udpLen:], uint16(8+len(answer)))
	out[udpChecksum], out[udpChecksum+1] = 0, 0 // optional for IPv4

	copy(out[udpPayloadOff:], answer)

	// Recompute the IPv4 header checksum over the 20-byte header.
	out[ipChecksumOff], out[ipChecksumOff+1] = 0, 0
	binary.BigEndian.PutUint16(out[ipChecksumOff:], ipChecksum(out[14:34]))

	return total
}

// ipChecksum computes the 16-bit one's-complement checksum of an IPv4 header.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
