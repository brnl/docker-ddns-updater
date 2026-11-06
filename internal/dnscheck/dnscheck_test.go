package dnscheck

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// authServer is a minimal authoritative DNS server over UDP for tests.
type authServer struct {
	conn    net.PacketConn
	mu      sync.Mutex
	records map[string][]netip.Addr // "name." -> addresses (A and AAAA)
	refuse  bool
	queries []string
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on UDP: %v", err)
	}
	s := &authServer{conn: conn, records: map[string][]netip.Addr{}}
	t.Cleanup(func() { conn.Close() })
	go s.serve()
	return s
}

func (s *authServer) set(name string, addrs ...netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[name] = addrs
}

func (s *authServer) setRefuse(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuse = v
}

func (s *authServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.queries...)
}

func (s *authServer) port() string {
	_, p, _ := net.SplitHostPort(s.conn.LocalAddr().String())
	return p
}

func (s *authServer) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if resp := s.answer(buf[:n]); resp != nil {
			_, _ = s.conn.WriteTo(resp, addr)
		}
	}
}

func (s *authServer) answer(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	// Parse the question name.
	i, labels := 12, []string{}
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	name := strings.ToLower(strings.Join(labels, ".")) + "."
	qtype := binary.BigEndian.Uint16(q[i+1:])
	question := q[12 : i+5]

	s.mu.Lock()
	s.queries = append(s.queries, name)
	addrs, known := s.records[name]
	refuse := s.refuse
	s.mu.Unlock()

	flags := uint16(0x8400) // QR, AA
	var answers [][]byte
	switch {
	case refuse:
		flags = 0x8005 // QR, REFUSED
	case !known:
		flags |= 3 // NXDOMAIN
	default:
		for _, a := range addrs {
			if (qtype == 1 && a.Is4()) || (qtype == 28 && a.Is6()) {
				raw := a.AsSlice()
				rr := []byte{0xc0, 0x0c, 0, byte(qtype), 0, 1, 0, 0, 0, 60, 0, byte(len(raw))}
				answers = append(answers, append(rr, raw...))
			}
		}
	}
	var b bytes.Buffer
	b.Write(q[:2]) // ID
	_ = binary.Write(&b, binary.BigEndian, []uint16{flags, 1, uint16(len(answers)), 0, 0})
	b.Write(question)
	for _, a := range answers {
		b.Write(a)
	}
	return b.Bytes()
}

// fakeRecursive answers NS and nameserver-address lookups.
type fakeRecursive struct {
	ns      map[string][]string     // zone. -> nameserver names
	addrs   map[string][]netip.Addr // name. -> addresses (nameservers and fallback answers)
	nsErr   error
	nsCalls int
	ipCalls []string
}

func (f *fakeRecursive) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	f.nsCalls++
	if f.nsErr != nil {
		return nil, f.nsErr
	}
	hosts, ok := f.ns[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	var out []*net.NS
	for _, h := range hosts {
		out = append(out, &net.NS{Host: h})
	}
	return out, nil
}

func (f *fakeRecursive) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.ipCalls = append(f.ipCalls, network+" "+host)
	a, ok := f.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, x := range a {
		if network == "ip" || (network == "ip4") == x.Is4() {
			out = append(out, x)
		}
	}
	return out, nil
}

type fixture struct {
	srv  *authServer
	rec  *fakeRecursive
	r    *Resolver
	logs *bytes.Buffer
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	srv := newAuthServer(t)
	f := &fixture{
		srv: srv,
		rec: &fakeRecursive{
			ns: map[string][]string{"example.com.": {"ns1.example.net.", "ns2.example.net."}},
			addrs: map[string][]netip.Addr{
				"ns1.example.net.": {netip.MustParseAddr("127.0.0.1")},
				"ns2.example.net.": {netip.MustParseAddr("::1")},
				// What a caching/split-horizon resolver would say:
				"home.example.com.": {netip.MustParseAddr("198.51.100.1")},
			},
		},
		logs: &bytes.Buffer{},
		now:  time.Unix(1_700_000_000, 0),
	}
	f.r = New(f.rec, 2*time.Second, slog.New(slog.NewTextHandler(f.logs, nil)))
	f.r.port = srv.port()
	f.r.now = func() time.Time { return f.now }
	srv.set("home.example.com.", netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::7"))
	return f
}

func TestAuthoritativeAnswer(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	got, err := f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("ip4 = %v, %v (want the authoritative 203.0.113.7, not the resolver's answer)", got, err)
	}
	got, err = f.r.LookupNetIP(ctx, "ip6", "home.example.com")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("ip6 = %v, %v", got, err)
	}
	// The zone was found by walking up from the hostname, and queries used
	// the rooted name (no search domains).
	if q := f.srv.seen(); len(q) == 0 || q[0] != "home.example.com." {
		t.Errorf("queries = %v", q)
	}
	if !strings.Contains(f.logs.String(), "zone=example.com") || !strings.Contains(f.logs.String(), "ns1.example.net,ns2.example.net") {
		t.Errorf("nameservers not logged: %s", f.logs.String())
	}
}

func TestNotFoundIsNotFallback(t *testing.T) {
	f := newFixture(t)
	f.rec.addrs["new.example.com."] = []netip.Addr{netip.MustParseAddr("198.51.100.9")} // stale cache
	_, err := f.r.LookupNetIP(context.Background(), "ip4", "new.example.com")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("err = %v, want the authoritative NXDOMAIN", err)
	}
	if strings.Contains(strings.Join(f.rec.ipCalls, " "), "new.example.com") {
		t.Error("fell back to the resolver on an authoritative NXDOMAIN")
	}
}

func TestFallbackWhenRefusedAndRecovery(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.srv.setRefuse(true)
	got, err := f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("fallback = %v, %v", got, err)
	}
	if !strings.Contains(f.logs.String(), "authoritative DNS lookup failed") {
		t.Errorf("fallback not logged: %s", f.logs.String())
	}
	f.logs.Reset()
	f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	if strings.Contains(f.logs.String(), "authoritative DNS lookup failed") {
		t.Error("unchanged fallback logged again immediately")
	}
	f.srv.setRefuse(false)
	if got, _ := f.r.LookupNetIP(ctx, "ip4", "home.example.com"); got[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("not back on the authoritative answer: %v", got)
	}
	if !strings.Contains(f.logs.String(), "authoritative DNS lookups work again") {
		t.Errorf("recovery not logged: %s", f.logs.String())
	}
}

func TestDiscoveryCachingAndFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	calls := f.rec.nsCalls // home.example.com. (not found), example.com.
	f.r.LookupNetIP(ctx, "ip6", "home.example.com")
	f.now = f.now.Add(59 * time.Minute)
	f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	if f.rec.nsCalls != calls {
		t.Fatalf("nameservers looked up again within the cache TTL: %d -> %d", calls, f.rec.nsCalls)
	}
	f.now = f.now.Add(2 * time.Minute)
	f.r.LookupNetIP(ctx, "ip4", "home.example.com")
	if f.rec.nsCalls == calls {
		t.Fatal("nameservers not refreshed after the cache TTL")
	}

	// No NS anywhere (only the TLD would have them): fall back, and
	// remember the failure for a while.
	g := newFixture(t)
	g.rec.addrs["host.other.org."] = []netip.Addr{netip.MustParseAddr("198.51.100.5")}
	got, err := g.r.LookupNetIP(ctx, "ip4", "host.other.org")
	if err != nil || got[0] != netip.MustParseAddr("198.51.100.5") {
		t.Fatalf("fallback = %v, %v", got, err)
	}
	if strings.Contains(strings.Join(g.srv.seen(), " "), "other.org") {
		t.Error("queried something although no nameservers were found")
	}
	n := g.rec.nsCalls
	g.r.LookupNetIP(ctx, "ip4", "host.other.org")
	if g.rec.nsCalls != n {
		t.Error("failed discovery not cached")
	}
}

func TestNeverQueriesTLD(t *testing.T) {
	f := newFixture(t)
	f.rec.ns["org."] = []string{"a0.org-servers.example."}
	e := f.r.discover(context.Background(), "host.other.org")
	if e.err == nil || e.zone == "org" {
		t.Fatalf("used the TLD as zone: %+v", e)
	}
}

func TestWildcardAndTrailingDot(t *testing.T) {
	f := newFixture(t)
	if e := f.r.discover(context.Background(), "*.example.com"); e.err != nil || e.zone != "example.com" {
		t.Errorf("wildcard: %+v", e)
	}
	if e := f.r.discover(context.Background(), "home.example.com."); e.err != nil || e.zone != "example.com" {
		t.Errorf("trailing dot: %+v", e)
	}
}

func TestDiscoveryErrorFallsBack(t *testing.T) {
	f := newFixture(t)
	f.rec.nsErr = errors.New("i/o timeout")
	got, err := f.r.LookupNetIP(context.Background(), "ip4", "home.example.com")
	if err != nil || got[0] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("fallback = %v, %v", got, err)
	}
	if !strings.Contains(f.logs.String(), "looking up the nameservers of home.example.com") {
		t.Errorf("discovery error not logged: %s", f.logs.String())
	}
}
