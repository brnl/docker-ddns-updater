// Package updater runs the detect-compare-update loop.
package updater

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/ipdetect"
	"github.com/brnl/docker-ddns-updater/internal/provider"
)

const (
	maxBackoff       = 30 * time.Minute
	permanentBackoff = time.Hour
)

// Detector reports the current public address of one family.
type Detector interface {
	Family() ipdetect.Family
	Detect(ctx context.Context) (netip.Addr, error)
}

// Resolver looks up the addresses currently published in DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// HealthReporter receives the outcome of every check cycle.
type HealthReporter interface {
	Tick(ok bool)
}

// Options configures an Updater.
type Options struct {
	Provider  provider.Provider
	Detectors []Detector
	Hostnames []string
	Interval  time.Duration
	// DNSRecheckInterval controls how often the published DNS records are
	// compared with the detected address. Records are always looked up at
	// startup; 0 disables the periodic re-check.
	DNSRecheckInterval time.Duration
	Resolver           Resolver
	Health             HealthReporter
	DryRun             bool
	Logger             *slog.Logger
	Now                func() time.Time
}

type hostState struct {
	known       map[ipdetect.Family]netip.Addr // what we believe is in DNS
	lastSync    time.Time                      // last DNS lookup or successful update
	failures    int
	nextAttempt time.Time
	lastUpdate  time.Time
	lastError   string
	lastErrorAt time.Time
	inSync      bool
	// dnsWarnings holds a warning per family when the resolver returned
	// only non-public addresses (split-horizon DNS).
	dnsWarnings map[ipdetect.Family]string
	updatesOK   uint64
	updatesFail uint64
}

type familyState struct {
	changedAt  time.Time
	err        string
	detectOK   uint64
	detectFail uint64
	changes    uint64
}

// Snapshot is a point-in-time view of the updater state, for status pages.
type Snapshot struct {
	LastCheck time.Time      `json:"last_check,omitzero"`
	Families  []FamilyStatus `json:"families"`
	Hosts     []HostStatus   `json:"hosts"`
}

// FamilyStatus describes the detected public address of one family.
type FamilyStatus struct {
	Family     string    `json:"family"`
	Address    string    `json:"address,omitempty"`
	ChangedAt  time.Time `json:"changed_at,omitzero"`
	Error      string    `json:"error,omitempty"`
	Detections uint64    `json:"detections"`
	Failures   uint64    `json:"detection_failures"`
	Changes    uint64    `json:"changes"`
}

// HostStatus describes one managed hostname.
type HostStatus struct {
	Hostname    string    `json:"hostname"`
	IPv4        string    `json:"ipv4,omitempty"`
	IPv6        string    `json:"ipv6,omitempty"`
	InSync      bool      `json:"in_sync"`
	LastUpdate  time.Time `json:"last_update,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
	Failures    int       `json:"failures"`
	DNSWarning  string    `json:"dns_warning,omitempty"`
	UpdatesOK   uint64    `json:"updates_succeeded"`
	UpdatesFail uint64    `json:"updates_failed"`
}

// Updater keeps DNS records in sync with the public IP address.
type Updater struct {
	opts       Options
	log        *slog.Logger
	hosts      map[string]*hostState
	current    map[ipdetect.Family]netip.Addr
	detectErrs map[ipdetect.Family]string
	families   map[ipdetect.Family]*familyState
	lastCheck  time.Time
	snapshot   atomic.Pointer[Snapshot]
}

// New returns an Updater.
func New(opts Options) *Updater {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	hosts := make(map[string]*hostState, len(opts.Hostnames))
	for _, h := range opts.Hostnames {
		hosts[h] = &hostState{known: map[ipdetect.Family]netip.Addr{}, dnsWarnings: map[ipdetect.Family]string{}}
	}
	families := map[ipdetect.Family]*familyState{}
	for _, d := range opts.Detectors {
		families[d.Family()] = &familyState{}
	}
	u := &Updater{
		opts:       opts,
		log:        opts.Logger,
		hosts:      hosts,
		current:    map[ipdetect.Family]netip.Addr{},
		detectErrs: map[ipdetect.Family]string{},
		families:   families,
	}
	u.publish()
	return u
}

// Snapshot returns the state as of the last completed check cycle. It is safe
// to call concurrently with Run.
func (u *Updater) Snapshot() Snapshot { return *u.snapshot.Load() }

func (u *Updater) publish() {
	s := &Snapshot{LastCheck: u.lastCheck}
	fams := make([]ipdetect.Family, 0, len(u.families))
	for f := range u.families {
		fams = append(fams, f)
	}
	sort.Slice(fams, func(i, j int) bool { return fams[i] < fams[j] })
	for _, f := range fams {
		st := u.families[f]
		fs := FamilyStatus{
			Family:     f.String(),
			ChangedAt:  st.changedAt,
			Error:      st.err,
			Detections: st.detectOK,
			Failures:   st.detectFail,
			Changes:    st.changes,
		}
		if a := u.current[f]; a.IsValid() {
			fs.Address = a.String()
		}
		s.Families = append(s.Families, fs)
	}
	for _, h := range u.opts.Hostnames {
		st := u.hosts[h]
		hs := HostStatus{
			Hostname:    h,
			InSync:      st.inSync,
			LastUpdate:  st.lastUpdate,
			LastError:   st.lastError,
			LastErrorAt: st.lastErrorAt,
			NextAttempt: st.nextAttempt,
			Failures:    st.failures,
			UpdatesOK:   st.updatesOK,
			UpdatesFail: st.updatesFail,
		}
		var warnings []string
		for _, f := range []ipdetect.Family{ipdetect.IPv4, ipdetect.IPv6} {
			if w := st.dnsWarnings[f]; w != "" {
				warnings = append(warnings, w)
			}
		}
		hs.DNSWarning = strings.Join(warnings, "; ")
		if a := st.known[ipdetect.IPv4]; a.IsValid() {
			hs.IPv4 = a.String()
		}
		if a := st.known[ipdetect.IPv6]; a.IsValid() {
			hs.IPv6 = a.String()
		}
		s.Hosts = append(s.Hosts, hs)
	}
	u.snapshot.Store(s)
}

// Run checks immediately and then every Interval until ctx is cancelled.
func (u *Updater) Run(ctx context.Context) {
	ticker := time.NewTicker(u.opts.Interval)
	defer ticker.Stop()
	for {
		u.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check runs a single detect-compare-update cycle.
func (u *Updater) Check(ctx context.Context) {
	detected := u.detect(ctx)
	ok := len(detected) > 0
	if ok {
		for _, h := range u.opts.Hostnames {
			if ctx.Err() != nil {
				return
			}
			if !u.syncHost(ctx, h, detected) {
				ok = false
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	u.lastCheck = u.opts.Now()
	u.publish()
	if u.opts.Health != nil {
		u.opts.Health.Tick(ok)
	}
}

func (u *Updater) detect(ctx context.Context) map[ipdetect.Family]netip.Addr {
	type result struct {
		addr netip.Addr
		err  error
	}
	results := make([]result, len(u.opts.Detectors))
	var wg sync.WaitGroup
	for i, d := range u.opts.Detectors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := d.Detect(ctx)
			results[i] = result{addr, err}
		}()
	}
	wg.Wait()

	detected := map[ipdetect.Family]netip.Addr{}
	for i, d := range u.opts.Detectors {
		fam, r := d.Family(), results[i]
		if r.err != nil {
			if ctx.Err() != nil {
				continue
			}
			// Only log when the error changes, to avoid a log line every tick.
			if msg := r.err.Error(); u.detectErrs[fam] != msg {
				u.log.Warn("public IP detection failed", "family", fam.String(), "error", msg)
				u.detectErrs[fam] = msg
			}
			u.families[fam].err = r.err.Error()
			u.families[fam].detectFail++
			continue
		}
		if u.detectErrs[fam] != "" {
			u.log.Info("public IP detection recovered", "family", fam.String())
			delete(u.detectErrs, fam)
		}
		u.families[fam].err = ""
		u.families[fam].detectOK++
		if prev := u.current[fam]; prev != r.addr {
			if prev.IsValid() {
				u.log.Info("public IP changed", "family", fam.String(), "old", prev.String(), "new", r.addr.String())
				u.families[fam].changes++
			} else {
				u.log.Info("public IP detected", "family", fam.String(), "ip", r.addr.String())
			}
			u.current[fam] = r.addr
			u.families[fam].changedAt = u.opts.Now()
		}
		detected[fam] = r.addr
	}
	return detected
}

// syncHost updates hostname if needed and reports whether it is (believed to
// be) up to date.
func (u *Updater) syncHost(ctx context.Context, hostname string, detected map[ipdetect.Family]netip.Addr) bool {
	st := u.hosts[hostname]
	now := u.opts.Now()
	if now.Before(st.nextAttempt) {
		return false
	}
	if st.lastSync.IsZero() || (u.opts.DNSRecheckInterval > 0 && now.Sub(st.lastSync) >= u.opts.DNSRecheckInterval) {
		u.lookupDNS(ctx, hostname, st, detected)
		st.lastSync = now
	}

	var changed []any
	for fam, addr := range detected {
		if st.known[fam] != addr {
			old := "none"
			if st.known[fam].IsValid() {
				old = st.known[fam].String()
			}
			changed = append(changed, fam.String()+"_old", old)
		}
	}
	if len(changed) == 0 {
		st.inSync = true
		return true
	}
	st.inSync = false

	// Always send every detected family, so a partial update never makes the
	// provider fall back to the request's source address.
	req := provider.Request{Hostname: hostname, IPv4: detected[ipdetect.IPv4], IPv6: detected[ipdetect.IPv6]}
	attrs := append([]any{"hostname", hostname, "provider", u.opts.Provider.Name()}, changed...)
	if req.IPv4.IsValid() {
		attrs = append(attrs, "ipv4", req.IPv4.String())
	}
	if req.IPv6.IsValid() {
		attrs = append(attrs, "ipv6", req.IPv6.String())
	}

	if u.opts.DryRun {
		u.log.Info("dry run: would update DNS record", attrs...)
	} else if err := u.opts.Provider.Update(ctx, req); err != nil {
		if ctx.Err() != nil {
			return false
		}
		st.failures++
		backoff := u.backoff(st.failures)
		if provider.IsPermanent(err) {
			backoff = permanentBackoff
		}
		st.nextAttempt = now.Add(backoff)
		st.lastError = err.Error()
		st.lastErrorAt = now
		st.updatesFail++
		u.log.Error("DNS update failed", append(attrs, "error", err.Error(), "retry_in", backoff.String())...)
		return false
	} else {
		u.log.Info("DNS record updated", attrs...)
	}

	for fam, addr := range detected {
		st.known[fam] = addr
	}
	if !u.opts.DryRun {
		st.updatesOK++
	}
	st.lastSync = now
	st.lastUpdate = now
	st.lastError = ""
	st.failures = 0
	st.nextAttempt = time.Time{}
	st.inSync = true
	return true
}

// lookupDNS refreshes st.known from the published records.
//
// Only public addresses count as published records. A resolver that only
// returns private or otherwise non-routable addresses is almost certainly
// split-horizon DNS (an internal view of the zone); its answer says nothing
// about the public record, so the last known value is kept and a warning is
// raised instead.
func (u *Updater) lookupDNS(ctx context.Context, hostname string, st *hostState, detected map[ipdetect.Family]netip.Addr) {
	for fam, cur := range detected {
		network := "ip4"
		if fam == ipdetect.IPv6 {
			network = "ip6"
		}
		addrs, err := u.opts.Resolver.LookupNetIP(ctx, network, hostname)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				st.known[fam] = netip.Addr{}
				u.setDNSWarning(hostname, st, fam, "")
				u.log.Debug("no DNS record found", "hostname", hostname, "family", fam.String())
			} else {
				u.log.Debug("DNS lookup failed", "hostname", hostname, "family", fam.String(), "error", err.Error())
			}
			continue
		}
		var (
			published netip.Addr
			private   []string
		)
		for _, a := range addrs {
			a = a.Unmap()
			if !ipdetect.IsPublic(a) {
				private = append(private, a.String())
				continue
			}
			if a == cur {
				published = a
				break
			}
			if !published.IsValid() {
				published = a
			}
		}
		if !published.IsValid() && len(private) > 0 {
			u.setDNSWarning(hostname, st, fam, fmt.Sprintf(
				"DNS returned only non-public %s address(es) %s; ignoring (split-horizon DNS? set DDNS_DNS_SERVER to a public resolver)",
				fam, strings.Join(private, ", ")))
			continue
		}
		u.setDNSWarning(hostname, st, fam, "")
		if published != st.known[fam] {
			u.log.Debug("DNS record differs from last known value", "hostname", hostname, "family", fam.String(), "dns", published.String())
		}
		st.known[fam] = published
	}
}

// setDNSWarning records (or clears) a DNS warning, logging only on change.
func (u *Updater) setDNSWarning(hostname string, st *hostState, fam ipdetect.Family, msg string) {
	if st.dnsWarnings[fam] == msg {
		return
	}
	if msg != "" {
		u.log.Warn("ignoring DNS answer", "hostname", hostname, "family", fam.String(), "reason", msg)
		st.dnsWarnings[fam] = msg
	} else {
		delete(st.dnsWarnings, fam)
	}
}

func (u *Updater) backoff(failures int) time.Duration {
	d := u.opts.Interval
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	return min(d, maxBackoff)
}
