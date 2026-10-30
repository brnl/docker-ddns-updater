package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
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
func (p *fakeProvider) Update(_ context.Context, r provider.Request) (string, error) {
	p.reqs = append(p.reqs, r)
	if p.err != nil {
		return "", p.err
	}
	return "good", nil
}

type fakeResolver struct {
	records map[string][]netip.Addr // network -> addrs
	calls   int
	err     error
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if a := r.records[network]; len(a) > 0 {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func ip(s string) netip.Addr         { return netip.MustParseAddr(s) }

type fixture struct {
	v4, v6 *fakeDetector
	prov   *fakeProvider
	res    *fakeResolver
	clk    *clock
	u      *Updater
	logs   *bytes.Buffer
}

type logLine struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	State string `json:"state"`
	After string `json:"after"`
	N     int    `json:"failed_attempts"`
}

// lines returns the log lines written since the last call.
func (f *fixture) lines(t *testing.T) []logLine {
	t.Helper()
	var out []logLine
	for _, l := range strings.Split(strings.TrimSpace(f.logs.String()), "\n") {
		if l == "" {
			continue
		}
		var ll logLine
		if err := json.Unmarshal([]byte(l), &ll); err != nil {
			t.Fatalf("bad log line %q: %v", l, err)
		}
		out = append(out, ll)
	}
	f.logs.Reset()
	return out
}

func find(lines []logLine, msgPrefix string) *logLine {
	for i := range lines {
		if strings.HasPrefix(lines[i].Msg, msgPrefix) {
			return &lines[i]
		}
	}
	return nil
}

func newFixture(dnsRecheck time.Duration, detectors ...ipdetect.Family) *fixture {
	f := &fixture{
		v4:   &fakeDetector{family: ipdetect.IPv4, addr: ip("203.0.113.1")},
		v6:   &fakeDetector{family: ipdetect.IPv6, addr: ip("2001:db8::1")},
		prov: &fakeProvider{},
		res:  &fakeResolver{records: map[string][]netip.Addr{}},
		clk:  &clock{t: time.Unix(1_700_000_000, 0)},
		logs: &bytes.Buffer{},
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
		Logger:             slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Now:                f.clk.now,
		Heartbeat:          time.Hour,
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

func TestSplitHorizonDNSIsIgnored(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()

	// The record is correct, so nothing should be sent.
	f.res.records["ip4"] = []netip.Addr{ip("203.0.113.1")}
	f.u.Check(ctx)
	if len(f.prov.reqs) != 0 {
		t.Fatalf("unexpected update: %v", f.prov.reqs)
	}

	// The resolver switches to an internal view: the private answer must not
	// replace the known public record (and must not trigger an update).
	f.res.records["ip4"] = []netip.Addr{ip("192.168.1.10")}
	f.clk.add(61 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 0 {
		t.Fatalf("private DNS answer triggered an update: %v", f.prov.reqs)
	}
	h := f.u.Snapshot().Hosts[0]
	if h.DNSWarning == "" || h.IPv4 != "203.0.113.1" || !h.InSync {
		t.Fatalf("host = %+v", h)
	}

	// A mix of private and public addresses uses the public one; the warning clears.
	f.res.records["ip4"] = []netip.Addr{ip("10.0.0.5"), ip("198.51.100.9")}
	f.clk.add(61 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 {
		t.Fatalf("public drift not corrected: %v", f.prov.reqs)
	}
	if h := f.u.Snapshot().Hosts[0]; h.DNSWarning != "" {
		t.Fatalf("warning not cleared: %+v", h)
	}
}

func TestSplitHorizonAtStartupStillUpdates(t *testing.T) {
	// With only a private answer at startup the public record is unknown, so
	// one update is sent (the provider answers nochg if it was correct).
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.res.records["ip4"] = []netip.Addr{ip("192.168.1.10")}
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 || f.u.Snapshot().Hosts[0].DNSWarning == "" {
		t.Fatalf("reqs = %v, host = %+v", f.prov.reqs, f.u.Snapshot().Hosts[0])
	}
}

func TestCounters(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.u.Check(ctx) // update ok
	f.v4.addr = ip("203.0.113.2")
	f.prov.err = errors.New("boom")
	f.clk.add(10 * time.Second)
	f.u.Check(ctx) // change + update failure
	f.v4.err = errors.New("down")
	f.clk.add(10 * time.Second)
	f.u.Check(ctx) // detection failure

	s := f.u.Snapshot()
	fam, h := s.Families[0], s.Hosts[0]
	if fam.Detections != 2 || fam.Failures != 1 || fam.Changes != 1 {
		t.Errorf("family = %+v", fam)
	}
	if h.UpdatesOK != 1 || h.UpdatesFail != 1 {
		t.Errorf("host = %+v", h)
	}
}

func TestLogsDetectionFailureReminderAndRecovery(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.u.Check(ctx)
	f.lines(t)

	f.v4.err = errors.New("all sources down")
	f.clk.add(time.Minute)
	f.u.Check(ctx)
	if l := find(f.lines(t), "public IP detection failed"); l == nil || l.Level != "ERROR" || l.State != "started" {
		t.Fatalf("failure not logged as started error: %+v", l)
	}
	f.clk.add(time.Minute)
	f.u.Check(ctx)
	if l := find(f.lines(t), "public IP detection failed"); l != nil {
		t.Fatal("unchanged failure logged again immediately")
	}
	f.clk.add(15 * time.Minute)
	f.u.Check(ctx)
	if l := find(f.lines(t), "public IP detection failed"); l == nil || l.State != "ongoing" {
		t.Fatalf("no reminder for ongoing failure: %+v", l)
	}
	f.v4.err = nil
	f.clk.add(time.Minute)
	f.u.Check(ctx)
	if l := find(f.lines(t), "public IP detection recovered"); l == nil || l.N != 3 || l.After != "17m0s" {
		t.Fatalf("recovery not logged with duration and attempts: %+v", l)
	}
}

func TestLogsUpdateFailureAndRecovery(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.prov.err = errors.New("timeout")
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS update failed"); l == nil || l.Level != "ERROR" {
		t.Fatalf("update failure not logged: %+v", l)
	}
	f.prov.err = nil
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS update recovered"); l == nil || l.N != 1 || l.After != "10s" {
		t.Fatalf("update recovery not logged: %+v", l)
	}

	f.prov.err = &provider.PermanentError{Err: errors.New("badauth")}
	f.v4.addr = ip("203.0.113.9")
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS update rejected by provider"); l == nil {
		t.Fatal("permanent failure not logged with a hint")
	}
}

func TestLogsInitialState(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.res.records["ip4"] = []netip.Addr{ip("203.0.113.1")}
	f.u.Check(context.Background())
	if l := find(f.lines(t), "DNS record is up to date"); l == nil {
		t.Fatal("initial in-sync state not logged")
	}

	g := newFixture(time.Minute, ipdetect.IPv4)
	g.u.Check(context.Background())
	lines := g.lines(t)
	if find(lines, "DNS record differs from the public IP") == nil || find(lines, "DNS record updated") == nil {
		t.Fatalf("initial out-of-sync state not logged: %+v", lines)
	}
}

func TestLogsDNSLookupFailure(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.res.err = errors.New("i/o timeout")
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS lookup failed"); l == nil || l.Level != "WARN" {
		t.Fatalf("lookup failure not logged as warning: %+v", l)
	}
	f.res.err = nil
	f.clk.add(61 * time.Second)
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS lookup recovered"); l == nil {
		t.Fatal("lookup recovery not logged")
	}
}

func TestHeartbeat(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.u.Check(ctx)
	if find(f.lines(t), "status:") != nil {
		t.Fatal("heartbeat before interval elapsed")
	}
	f.clk.add(time.Hour)
	f.u.Check(ctx)
	if l := find(f.lines(t), "status: all hostnames up to date"); l == nil || l.Level != "INFO" {
		t.Fatalf("healthy heartbeat missing: %+v", l)
	}
	f.prov.err = errors.New("boom")
	f.v4.addr = ip("203.0.113.2")
	f.clk.add(time.Hour)
	f.u.Check(ctx)
	if l := find(f.lines(t), "status: degraded"); l == nil || l.Level != "WARN" {
		t.Fatalf("degraded heartbeat missing: %+v", l)
	}
}

func TestStopOnRejection(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.prov.err = &provider.PermanentError{Err: errors.New("badauth"), Stop: true}
	f.u.Check(ctx)
	if l := find(f.lines(t), "DNS update rejected by provider; updates for this hostname are stopped"); l == nil || l.Level != "ERROR" {
		t.Fatalf("stop not logged: %+v", l)
	}
	// No further requests, however long we wait or whatever changes.
	f.prov.err = nil
	f.v4.addr = ip("203.0.113.9")
	for i := 0; i < 5; i++ {
		f.clk.add(24 * time.Hour)
		f.u.Check(ctx)
	}
	if len(f.prov.reqs) != 1 {
		t.Fatalf("updates sent after stop: %d", len(f.prov.reqs))
	}
	h := f.u.Snapshot().Hosts[0]
	if !h.Stopped || h.InSync || !h.NextAttempt.IsZero() {
		t.Fatalf("host = %+v", h)
	}
	if find(f.lines(t), "status: degraded") == nil {
		t.Error("heartbeat does not report degraded state")
	}
}

func TestRetryAfter(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	ctx := context.Background()
	f.prov.err = &provider.RetryAfterError{Err: errors.New("911"), After: 30 * time.Minute}
	f.u.Check(ctx)
	f.prov.err = nil
	f.clk.add(29 * time.Minute)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 1 {
		t.Fatalf("retried before 30m: %d requests", len(f.prov.reqs))
	}
	f.clk.add(time.Minute)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 2 {
		t.Fatalf("not retried after 30m: %d requests", len(f.prov.reqs))
	}
}

func TestAccountWideStop(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4)
	f.u = New(Options{
		Provider:  f.prov,
		Detectors: []Detector{f.v4},
		Hostnames: []string{"a.example.com", "b.example.com", "c.example.com"},
		Interval:  10 * time.Second, DNSRecheckInterval: time.Minute,
		Resolver: f.res, Logger: quiet(), Now: f.clk.now,
	})
	f.prov.err = &provider.PermanentError{Err: errors.New("badauth"), Stop: true, Account: true}
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 {
		t.Fatalf("requests after account-wide rejection = %d, want 1", len(f.prov.reqs))
	}
	f.v4.addr = ip("203.0.113.9")
	f.clk.add(24 * time.Hour)
	f.u.Check(context.Background())
	if len(f.prov.reqs) != 1 {
		t.Fatalf("updates sent after account-wide stop: %d", len(f.prov.reqs))
	}
	for _, h := range f.u.Snapshot().Hosts {
		if !h.Stopped || h.LastError == "" {
			t.Errorf("host %s not stopped: %+v", h.Hostname, h)
		}
	}
}

func TestKeepsLastKnownAddressWhenDetectionFails(t *testing.T) {
	f := newFixture(time.Minute, ipdetect.IPv4, ipdetect.IPv6)
	ctx := context.Background()
	f.u.Check(ctx) // both families detected and sent
	// IPv4 changes while IPv6 detection fails: the update must still carry
	// the known IPv6 address so the AAAA record is not dropped.
	f.v4.addr = ip("203.0.113.2")
	f.v6.err = errors.New("no route")
	f.clk.add(10 * time.Second)
	f.u.Check(ctx)
	if len(f.prov.reqs) != 2 {
		t.Fatalf("requests = %d", len(f.prov.reqs))
	}
	r := f.prov.reqs[1]
	if r.IPv4 != ip("203.0.113.2") || r.IPv6 != ip("2001:db8::1") {
		t.Fatalf("request = %+v", r)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
