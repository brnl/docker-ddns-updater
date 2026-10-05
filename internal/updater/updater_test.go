package updater

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/ipdetect"
	"github.com/brnl/docker-ddns-updater/internal/provider"
)

type fakeDetector struct {
	family ipdetect.Family
	addr   netip.Addr
	err    error
}

func (d *fakeDetector) Family() ipdetect.Family { return d.family }
func (d *fakeDetector) Detect(context.Context) (netip.Addr, error) {
	return d.addr, d.err
}

type fakeProvider struct {
	reqs []provider.Request
	err  error
}

func (p *fakeProvider) Name() string { return "fake" }
func (p *fakeProvider) Update(_ context.Context, r provider.Request) error {
	p.reqs = append(p.reqs, r)
	return p.err
}

type fakeResolver struct {
	records map[string][]netip.Addr // network -> addrs
	calls   int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	if a := r.records[network]; len(a) > 0 {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func ip(s string) netip.Addr         { return netip.MustParseAddr(s) }
func quiet() *slog.Logger            { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fixture struct {
	v4, v6 *fakeDetector
	prov   *fakeProvider
	res    *fakeResolver
	clk    *clock
	u      *Updater
}

func newFixture(dnsRecheck time.Duration, detectors ...ipdetect.Family) *fixture {
	f := &fixture{
		v4:   &fakeDetector{family: ipdetect.IPv4, addr: ip("203.0.113.1")},
		v6:   &fakeDetector{family: ipdetect.IPv6, addr: ip("2001:db8::1")},
		prov: &fakeProvider{},
		res:  &fakeResolver{records: map[string][]netip.Addr{}},
		clk:  &clock{t: time.Unix(1_700_000_000, 0)},
	}
	var ds []Detector
	for _, fam := range detectors {
		if fam == ipdetect.IPv4 {
			ds = append(ds, f.v4)
		} else {
			ds = append(ds, f.v6)
		}
	}
	f.u = New(Options{
		Provider:           f.prov,
		Detectors:          ds,
		Hostnames:          []string{"home.example.com"},
		Interval:           10 * time.Second,
		DNSRecheckInterval: dnsRecheck,
		Resolver:           f.res,
		Logger:             quiet(),
		Now:                f.clk.now,
	})
	return f
}

func TestNoUpdateWhenDNSMatches(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.res.records["ip4"] = []netip.Addr{ip("203.0.113.1")}
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 0 {
		t.Fatalf("unexpected updates: %v", f.prov.reqs)
	}
}

func TestUpdateOnStartupMismatchAndOnChange(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.res.records["ip4"] = []netip.Addr{ip("198.51.100.9")}
	ctx := context.Background()

	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 || f.prov.reqs[0].IPv4 != ip("203.0.113.1") || f.prov.reqs[0].IPv6.IsValid() {
		t.Fatalf("reqs = %v", f.prov.reqs)
	}

	// Unchanged IP: no further updates, and no DNS lookups within the recheck interval.
	calls := f.res.calls
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 || f.res.calls != calls {
		t.Fatalf("unexpected update or lookup: reqs=%d calls=%d", len(f.prov.reqs), f.res.calls)
	}

	// IP changes: update.
	f.v4.addr = ip("203.0.113.2")
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 2 || f.prov.reqs[1].IPv4 != ip("203.0.113.2") {
		t.Fatalf("reqs = %v", f.prov.reqs)
	}
}

func TestDNSRecheckDetectsDrift(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.res.records["ip4"] = []netip.Addr{ip("203.0.113.1")}
	ctx := context.Background()
	f.u.Check(ctx)

	// Someone changes the record out of band.
	f.res.records["ip4"] = []netip.Addr{ip("198.51.100.9")}
	f.clk.add(30 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 0 {
		t.Fatal("updated before recheck interval")
	}
	f.clk.add(31 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 {
		t.Fatal("drift not corrected after recheck interval")
	}
}

func TestDualStackSendsBothFamilies(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4, ipdetect.IPv6)
	f.res.records["ip4"] = []netip.Addr{ip("203.0.113.1")}
	f.res.records["ip6"] = []netip.Addr{ip("2001:db8::99")}
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 {
		t.Fatalf("reqs = %v", f.prov.reqs)
	}
	r := f.prov.reqs[0]
	if r.IPv4 != ip("203.0.113.1") || r.IPv6 != ip("2001:db8::1") {
		t.Errorf("req = %+v", r)
	}
}

func TestIPv6OnlyAndDetectionFailure(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4, ipdetect.IPv6)
	f.v4.err = errors.New("no route")
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 || f.prov.reqs[0].IPv4.IsValid() || f.prov.reqs[0].IPv6 != ip("2001:db8::1") {
		t.Fatalf("reqs = %v", f.prov.reqs)
	}

	f.v6.err = errors.New("no route")
	f.clk.add(10 * time.Second)
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 {
		t.Fatal("update sent without any detected address")
	}
}

func TestBackoff(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.prov.err = errors.New("boom")
	ctx := context.Background()

	f.u.Check(ctx) // fail #1 -> retry in 10s
	f.clk.add(5 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 {
		t.Fatalf("retried during backoff: %d", len(f.prov.reqs))
	}
	f.clk.add(5 * time.Second)
	f.u.Check(ctx) // fail #2 -> retry in 20s
	if len(f.prov.reqs) != 2 {
		t.Fatalf("did not retry after backoff: %d", len(f.prov.reqs))
	}
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 2 {
		t.Fatal("backoff did not grow")
	}

	f.prov.err = &provider.PermanentError{Err: errors.New("badauth")}
	f.clk.add(10 * time.Second)
	f.u.Check(ctx) // permanent -> 1h
	f.clk.add(30 * time.Minute)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 3 {
		t.Fatalf("retried permanent error too soon: %d", len(f.prov.reqs))
	}

	f.prov.err = nil
	f.clk.add(31 * time.Minute)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 4 {
		t.Fatal("did not recover")
	}
}

func TestDryRun(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.u.opts.DryRun = true
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 0 {
		t.Fatal("dry run called provider")
	}
}

func TestSnapshot(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	if s := f.u.Snapshot(); !s.LastCheck.IsZero() || len(s.Hosts) != 1 || s.Hosts[0].InSync {
		t.Fatalf("initial snapshot = %+v", s)
	}
	f.u.Check(context.Background())
	s := f.u.Snapshot()
	if s.LastCheck.IsZero() || len(s.Families) != 1 || s.Families[0].Address != "203.0.113.1" {
		t.Fatalf("snapshot = %+v", s)
	}
	if h := s.Hosts[0]; !h.InSync || h.IPv4 != "203.0.113.1" || h.LastUpdate.IsZero() {
		t.Fatalf("host = %+v", h)
	}

	f.prov.err = errors.New("boom")
	f.v4.addr = ip("203.0.113.2")
	f.clk.add(10 * time.Second)
	f.u.Check(context.Background())
	if h := f.u.Snapshot().Hosts[0]; h.InSync || h.LastError != "boom" || h.Failures != 1 || h.NextAttempt.IsZero() {
		t.Fatalf("host = %+v", h)
	}
}
