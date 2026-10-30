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

	"github.com/brnl/docker-ddns-updater/internal/condlog"
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
	// Heartbeat is how often a status summary is logged; 0 disables it.
	Heartbeat time.Duration
	DryRun    bool
	Logger    *slog.Logger
	Now       func() time.Time
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
	// stopped is set when the provider requires that no further updates
	// are sent until the configuration is fixed (and the updater restarted).
	stopped bool
	// failure tracking for logging (start, reminders, recovery)
	updateErr condlog.Tracker
	lookupErr map[ipdetect.Family]*condlog.Tracker
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
	Stopped     bool      `json:"updates_stopped,omitempty"`
	UpdatesOK   uint64    `json:"updates_succeeded"`
	UpdatesFail uint64    `json:"updates_failed"`
}

// Updater keeps DNS records in sync with the public IP address.
type Updater struct {
	opts       Options
	log        *slog.Logger
	hosts      map[string]*hostState
	current    map[ipdetect.Family]netip.Addr
	detectErrs map[ipdetect.Family]*condlog.Tracker
	families   map[ipdetect.Family]*familyState
	lastCheck  time.Time
	snapshot   atomic.Pointer[Snapshot]

	started       time.Time
	lastHeartbeat time.Time
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
		st := &hostState{
			known:       map[ipdetect.Family]netip.Addr{},
			dnsWarnings: map[ipdetect.Family]string{},
			lookupErr:   map[ipdetect.Family]*condlog.Tracker{},
			// Every failed update is logged already (they are spaced out by
			// the backoff), so no reminders are needed.
			updateErr: condlog.Tracker{Reminder: -1},
		}
		for _, d := range opts.Detectors {
			st.lookupErr[d.Family()] = &condlog.Tracker{}
		}
		hosts[h] = st
	}
	families := map[ipdetect.Family]*familyState{}
	detectErrs := map[ipdetect.Family]*condlog.Tracker{}
	for _, d := range opts.Detectors {
		families[d.Family()] = &familyState{}
		detectErrs[d.Family()] = &condlog.Tracker{}
	}
	now := opts.Now()
	u := &Updater{
		opts:          opts,
		log:           opts.Logger,
		hosts:         hosts,
		current:       map[ipdetect.Family]netip.Addr{},
		detectErrs:    detectErrs,
		families:      families,
		started:       now,
		lastHeartbeat: now,
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
			Stopped:     st.stopped,
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
	u.heartbeat(ok)
}

// heartbeat periodically logs a one-line status summary, so the logs show
// the updater is alive and what it believes, even when nothing changes.
func (u *Updater) heartbeat(ok bool) {
	now := u.opts.Now()
	if u.opts.Heartbeat <= 0 || now.Sub(u.lastHeartbeat) < u.opts.Heartbeat {
		return
	}
	u.lastHeartbeat = now
	snap := u.Snapshot()
	attrs := []any{"uptime", now.Sub(u.started).Round(time.Second).String()}
	var detectFailing []string
	for _, f := range snap.Families {
		ip := f.Address
		if ip == "" {
			ip = "unknown"
		}
		attrs = append(attrs, f.Family, ip)
		if f.Error != "" {
			detectFailing = append(detectFailing, f.Family)
		}
	}
	var inSync int
	var outOfSync, failing, stopped []string
	var updatesOK, updatesFail uint64
	for _, h := range snap.Hosts {
		updatesOK += h.UpdatesOK
		updatesFail += h.UpdatesFail
		switch {
		case h.Stopped:
			stopped = append(stopped, h.Hostname)
		case h.Failures > 0:
			failing = append(failing, h.Hostname)
		case h.InSync:
			inSync++
		default:
			outOfSync = append(outOfSync, h.Hostname)
		}
	}
	attrs = append(attrs, "hosts", len(snap.Hosts), "in_sync", inSync,
		"updates_succeeded", updatesOK, "updates_failed", updatesFail)
	if len(outOfSync) > 0 {
		attrs = append(attrs, "out_of_sync", strings.Join(outOfSync, ","))
	}
	if len(failing) > 0 {
		attrs = append(attrs, "failing", strings.Join(failing, ","))
	}
	if len(stopped) > 0 {
		attrs = append(attrs, "updates_stopped", strings.Join(stopped, ","))
	}
	if len(detectFailing) > 0 {
		attrs = append(attrs, "detection_failing", strings.Join(detectFailing, ","))
	}
	if ok {
		u.log.Info("status: all hostnames up to date", attrs...)
	} else {
		u.log.Warn("status: degraded", attrs...)
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
		tr, now := u.detectErrs[fam], u.opts.Now()
		if r.err != nil {
			if ctx.Err() != nil {
				continue
			}
			// Logged when it starts, changes, and as a periodic reminder.
			if ev := tr.Fail(now, r.err.Error()); ev != condlog.None {
				u.log.Error("public IP detection failed; DNS records for this family are not updated",
					"family", fam.String(), "error", r.err.Error(), "state", ev.String(),
					"failing_for", now.Sub(tr.Since()).Round(time.Second).String(), "attempts", tr.Count())
			}
			u.families[fam].err = r.err.Error()
			u.families[fam].detectFail++
			continue
		}
		if ok, dur, n := tr.Recover(now); ok {
			u.log.Info("public IP detection recovered", "family", fam.String(), "ip", r.addr.String(),
				"after", dur.Round(time.Second).String(), "failed_attempts", n)
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
	if st.stopped || now.Before(st.nextAttempt) {
		return false
	}
	if first := st.lastSync.IsZero(); first || (u.opts.DNSRecheckInterval > 0 && now.Sub(st.lastSync) >= u.opts.DNSRecheckInterval) {
		u.lookupDNS(ctx, hostname, st, detected)
		st.lastSync = now
		if first {
			u.logInitialState(hostname, st, detected)
		}
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

	// Always send every enabled family, so a partial update never makes the
	// provider fall back to the request's source address or drop a record.
	// A family whose detection failed this cycle keeps its last known value.
	req := provider.Request{
		Hostname: hostname,
		IPv4:     u.addrForRequest(st, detected, ipdetect.IPv4),
		IPv6:     u.addrForRequest(st, detected, ipdetect.IPv6),
	}
	attrs := append([]any{"hostname", hostname, "provider", u.opts.Provider.Name()}, changed...)
	if req.IPv4.IsValid() {
		attrs = append(attrs, "ipv4", req.IPv4.String())
	}
	if req.IPv6.IsValid() {
		attrs = append(attrs, "ipv6", req.IPv6.String())
	}

	if u.opts.DryRun {
		u.log.Info("dry run: would update DNS record", attrs...)
	} else if resp, err := u.opts.Provider.Update(ctx, req); err != nil {
		if ctx.Err() != nil {
			return false
		}
		st.failures++
		st.lastError = err.Error()
		st.lastErrorAt = now
		st.updatesFail++
		st.updateErr.Fail(now, err.Error())
		attrs = append(attrs, "error", err.Error(), "attempt", st.failures,
			"failing_for", now.Sub(st.updateErr.Since()).Round(time.Second).String())

		if provider.StopsAllUpdates(err) {
			// Bad credentials or a blocked client: the provider requires the
			// client to stop entirely until the user fixes the problem.
			for _, other := range u.hosts {
				other.stopped = true
				other.nextAttempt = time.Time{}
				if other.lastError == "" {
					other.lastError, other.lastErrorAt = err.Error(), now
				}
			}
			u.log.Error("DNS update rejected by provider; updates for ALL hostnames are stopped until the configuration is fixed and the updater is restarted", attrs...)
			return false
		}
		if provider.StopsUpdates(err) {
			// The provider requires that the client stops until the user
			// fixes the problem; retrying risks getting the account blocked.
			st.stopped = true
			st.nextAttempt = time.Time{}
			u.log.Error("DNS update rejected by provider; updates for this hostname are stopped until the configuration is fixed and the updater is restarted", attrs...)
			return false
		}
		backoff := u.backoff(st.failures)
		permanent := provider.IsPermanent(err)
		if permanent {
			backoff = permanentBackoff
		}
		if after, ok := provider.RetryAfter(err); ok && after > backoff {
			backoff = after
		}
		st.nextAttempt = now.Add(backoff)
		msg := "DNS update failed"
		if permanent {
			msg = "DNS update rejected by provider; check the credentials and hostname"
		}
		u.log.Error(msg, append(attrs, "permanent", permanent, "retry_in", backoff.String())...)
		return false
	} else {
		attrs = append(attrs, "response", resp)
		if ok, dur, n := st.updateErr.Recover(now); ok {
			u.log.Info("DNS update recovered", append(attrs, "after", dur.Round(time.Second).String(), "failed_attempts", n)...)
		} else {
			u.log.Info("DNS record updated", attrs...)
		}
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

// addrForRequest returns the address to send for fam: the detected one, or,
// if detection failed this cycle, the last known record (or last detected
// address) so the provider keeps that record as it is.
func (u *Updater) addrForRequest(st *hostState, detected map[ipdetect.Family]netip.Addr, fam ipdetect.Family) netip.Addr {
	if a, ok := detected[fam]; ok {
		return a
	}
	if _, enabled := u.families[fam]; !enabled {
		return netip.Addr{}
	}
	if a := st.known[fam]; a.IsValid() {
		return a
	}
	return u.current[fam]
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
		tr, now := st.lookupErr[fam], u.opts.Now()
		var dnsErr *net.DNSError
		if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			if ctx.Err() == nil {
				if ev := tr.Fail(now, err.Error()); ev != condlog.None {
					u.log.Warn("DNS lookup failed; keeping the last known record", "hostname", hostname,
						"family", fam.String(), "error", err.Error(), "state", ev.String(),
						"failing_for", now.Sub(tr.Since()).Round(time.Second).String(), "attempts", tr.Count())
				}
			}
			continue
		}
		if ok, dur, n := tr.Recover(now); ok {
			u.log.Info("DNS lookup recovered", "hostname", hostname, "family", fam.String(),
				"after", dur.Round(time.Second).String(), "failed_attempts", n)
		}
		if err != nil { // not found
			st.known[fam] = netip.Addr{}
			u.setDNSWarning(hostname, st, fam, "")
			u.log.Debug("no DNS record found", "hostname", hostname, "family", fam.String())
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

// logInitialState logs, once per hostname at startup, what DNS currently
// publishes compared to the detected public address.
func (u *Updater) logInitialState(hostname string, st *hostState, detected map[ipdetect.Family]netip.Addr) {
	attrs := []any{"hostname", hostname}
	inSync := true
	for _, fam := range []ipdetect.Family{ipdetect.IPv4, ipdetect.IPv6} {
		cur, ok := detected[fam]
		if !ok {
			continue
		}
		dns := "none"
		switch {
		case st.known[fam].IsValid():
			dns = st.known[fam].String()
		case st.lookupErr[fam].Failing():
			dns = "unknown (lookup failed)"
		case st.dnsWarnings[fam] != "":
			dns = "unknown (only non-public answers)"
		}
		attrs = append(attrs, fam.String()+"_dns", dns, fam.String()+"_public", cur.String())
		inSync = inSync && st.known[fam] == cur
	}
	if inSync {
		u.log.Info("DNS record is up to date", attrs...)
	} else {
		u.log.Info("DNS record differs from the public IP; updating", attrs...)
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
