// Package dnscheck looks up the records published for a hostname directly at
// the authoritative nameservers of its zone, so the check always sees the
// provider's current data rather than a recursive resolver's cached (or
// split-horizon) answer. If that is not possible, it falls back to a regular
// resolver.
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/condlog"
	"github.com/brnl/docker-ddns-updater/internal/ipdetect"
)

const (
	// cacheTTL is how long discovered nameservers are reused.
	cacheTTL = time.Hour
	// negativeTTL is how long a failed discovery, or a zone whose
	// nameservers did not answer, is skipped (the resolver is used
	// meanwhile) before trying again.
	negativeTTL = 15 * time.Minute
	// serverTimeout bounds the query to one nameserver, so an unreachable
	// one is skipped quickly in favour of the next.
	serverTimeout = 3 * time.Second
)

// Recursive is a regular (recursive) resolver: it finds the nameservers and
// their addresses, and answers when the authoritative lookup is impossible.
type Recursive interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolver answers LookupNetIP from the authoritative nameservers.
type Resolver struct {
	recursive Recursive
	timeout   time.Duration
	log       *slog.Logger
	now       func() time.Time
	// port is the nameservers' DNS port; tests override it.
	port string
	// usable reports whether a nameserver address may be queried: only
	// public ones, so a (spoofed) NS record cannot point queries at
	// internal services. Tests override it.
	usable func(netip.Addr) bool

	mu       sync.Mutex
	hosts    map[string]*hostEntry       // hostname -> its zone
	zones    map[string]*zoneEntry       // zone -> nameservers
	fallback map[string]*condlog.Tracker // zone (or hostname) -> fallback state
}

type hostEntry struct {
	zone    string
	err     error  // discovery failed
	cname   string // the hostname is an alias for this name
	expires time.Time
	// loggedCNAME avoids repeating the alias notice at every refresh.
	loggedCNAME string
}

type zoneEntry struct {
	nameservers []string // host names, for logs
	servers     []string // "ip:port", IPv4 first
	err         error
	expires     time.Time
	// skipUntil is set when none of the nameservers answered.
	skipUntil time.Time
}

// cnameError reports that the hostname is an alias: its records live in
// another zone, so the resolver (which follows the alias) is used.
type cnameError struct{ target string }

func (e *cnameError) Error() string { return "hostname is a CNAME for " + e.target }

// New returns a Resolver that discovers nameservers with, and falls back to,
// recursive.
func New(recursive Recursive, timeout time.Duration, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Resolver{
		recursive: recursive,
		timeout:   timeout,
		log:       log,
		now:       time.Now,
		port:      "53",
		usable:    ipdetect.IsPublic,
		hosts:     map[string]*hostEntry{},
		zones:     map[string]*zoneEntry{},
		fallback:  map[string]*condlog.Tracker{},
	}
}

// LookupNetIP looks up host's addresses ("ip4" or "ip6") at its zone's
// authoritative nameservers. A "not found" answer from them is returned as
// is; any other failure falls back to the recursive resolver.
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	h, z := r.lookupZone(ctx, host)
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case h.cname != "":
		// An alias: expected, not a failure; the resolver follows it.
	case h.err != nil:
		r.failed(host, host, h.err)
	case z.err != nil:
		r.failed(h.zone, host, z.err)
	case r.now().Before(z.skipUntil):
		// The nameservers did not answer recently: don't wait for them on
		// every lookup (the failure is logged already).
	default:
		addrs, err := r.queryServers(ctx, z.servers, network, host)
		var dnsErr *net.DNSError
		var cname *cnameError
		switch {
		case err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound):
			r.recovered(h.zone)
			return addrs, err
		case ctx.Err() != nil:
			return nil, err
		case errors.As(err, &cname):
			r.mu.Lock()
			h.cname = cname.target
			logIt := h.loggedCNAME != cname.target
			h.loggedCNAME = cname.target
			r.mu.Unlock()
			if logIt {
				r.log.Info("hostname is an alias (CNAME); checking its records with the regular resolver",
					"hostname", host, "target", cname.target)
			}
		default:
			r.mu.Lock()
			z.skipUntil = r.now().Add(negativeTTL)
			r.mu.Unlock()
			r.failed(h.zone, host, fmt.Errorf("querying %s: %w", strings.Join(z.nameservers, ", "), err))
		}
	}
	return r.recursive.LookupNetIP(ctx, network, rooted(host))
}

// lookupZone returns host's (cached) zone and that zone's (cached)
// nameservers.
func (r *Resolver) lookupZone(ctx context.Context, host string) (*hostEntry, *zoneEntry) {
	now := r.now()
	r.mu.Lock()
	h := r.hosts[host]
	r.mu.Unlock()
	if h == nil || !now.Before(h.expires) {
		zone, err := r.findZone(ctx, host)
		if ctx.Err() != nil {
			return &hostEntry{err: ctx.Err()}, &zoneEntry{}
		}
		fresh := &hostEntry{zone: zone, err: err, expires: now.Add(cacheTTL)}
		if err != nil {
			fresh.expires = now.Add(negativeTTL)
		}
		if h != nil {
			fresh.loggedCNAME = h.loggedCNAME
		}
		h = fresh
		r.mu.Lock()
		r.hosts[host] = h
		r.mu.Unlock()
	}
	if h.err != nil {
		return h, &zoneEntry{}
	}

	r.mu.Lock()
	z := r.zones[h.zone]
	r.mu.Unlock()
	if z == nil || !now.Before(z.expires) {
		old := z
		z = r.zoneNameservers(ctx, h.zone)
		if ctx.Err() != nil {
			return h, z
		}
		if z.err == nil && (old == nil || !slices.Equal(old.nameservers, z.nameservers)) {
			r.log.Info("checking DNS records at the authoritative nameservers",
				"zone", h.zone, "nameservers", strings.Join(z.nameservers, ","))
		}
		r.mu.Lock()
		r.zones[h.zone] = z
		r.mu.Unlock()
	}
	return h, z
}

// findZone walks up from host ("a.b.example.com", "b.example.com",
// "example.com") to the closest name with NS records: the zone apex. The
// top-level domain is never used: its servers only delegate.
func (r *Resolver) findZone(ctx context.Context, host string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(labels) > 0 && labels[0] == "*" {
		labels = labels[1:]
	}
	for i := 0; i+2 <= len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		ns, err := r.recursive.LookupNS(ctx, rooted(zone))
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue // not a zone apex (or no NS records): go up
			}
			return "", fmt.Errorf("looking up the nameservers of %s: %w", zone, err)
		}
		if len(ns) > 0 {
			return zone, nil
		}
	}
	return "", fmt.Errorf("no nameservers found for %s", host)
}

// zoneNameservers looks up the nameservers of zone and their addresses.
func (r *Resolver) zoneNameservers(ctx context.Context, zone string) *zoneEntry {
	z := &zoneEntry{expires: r.now().Add(cacheTTL)}
	ns, err := r.recursive.LookupNS(ctx, rooted(zone))
	if err != nil {
		z.err = fmt.Errorf("looking up the nameservers of %s: %w", zone, err)
		z.expires = r.now().Add(negativeTTL)
		return z
	}
	var v4, v6 []string
	for _, n := range ns {
		name := strings.TrimSuffix(n.Host, ".")
		z.nameservers = append(z.nameservers, name)
		addrs, err := r.recursive.LookupNetIP(ctx, "ip", rooted(name))
		if err != nil {
			continue
		}
		for _, a := range addrs {
			a = a.Unmap()
			if !r.usable(a) {
				continue
			}
			hp := net.JoinHostPort(a.String(), r.port)
			if a.Is4() {
				v4 = append(v4, hp)
			} else {
				v6 = append(v6, hp)
			}
		}
	}
	slices.Sort(z.nameservers)
	// IPv4 first: IPv6 egress is often unavailable in containers.
	z.servers = append(v4, v6...)
	if len(z.servers) == 0 {
		z.err = fmt.Errorf("no public address found for the nameservers of %s (%s)", zone, strings.Join(z.nameservers, ", "))
		z.expires = r.now().Add(negativeTTL)
	}
	return z
}

// queryServers asks the nameservers one by one, each with its own time
// limit, until one gives an answer (records, or an authoritative "not
// found").
func (r *Resolver) queryServers(ctx context.Context, servers []string, network, host string) ([]netip.Addr, error) {
	var errs []error
	for _, s := range servers {
		addrs, err := r.queryServer(ctx, s, network, host)
		var dnsErr *net.DNSError
		var cname *cnameError
		if err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) || errors.As(err, &cname) || ctx.Err() != nil {
			return addrs, err
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (r *Resolver) queryServer(ctx context.Context, server, network, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, min(r.timeout, serverTimeout))
	defer cancel()
	dialer := &net.Dialer{}
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, proto, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, proto, server)
		},
	}
	name := rooted(host)
	addrs, err := res.LookupNetIP(ctx, network, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// The Go resolver names the server from /etc/resolv.conf here,
		// which was not queried.
		dnsErr.Server = server
		if dnsErr.IsNotFound {
			// "Not found" is also what an alias into another zone looks
			// like (the answer holds only the CNAME): tell them apart.
			if target, cerr := res.LookupCNAME(ctx, name); cerr == nil && !strings.EqualFold(target, name) {
				return nil, &cnameError{target: strings.TrimSuffix(target, ".")}
			}
		}
	}
	return addrs, err
}

func (r *Resolver) failed(key, host string, err error) {
	r.mu.Lock()
	tr, ok := r.fallback[key]
	if !ok {
		tr = &condlog.Tracker{}
		r.fallback[key] = tr
	}
	now := r.now()
	ev := tr.Fail(now, err.Error())
	since, attempts := tr.Since(), tr.Count()
	r.mu.Unlock()
	if ev != condlog.None {
		r.log.Warn("authoritative DNS lookup failed; using the regular resolver instead (its answer may be cached)",
			"hostname", host, "error", err.Error(), "state", ev.String(),
			"failing_for", now.Sub(since).Round(time.Second).String(), "attempts", attempts)
	}
}

func (r *Resolver) recovered(key string) {
	r.mu.Lock()
	tr, ok := r.fallback[key]
	var recovered bool
	var dur time.Duration
	if ok {
		recovered, dur, _ = tr.Recover(r.now())
	}
	r.mu.Unlock()
	if recovered {
		r.log.Info("authoritative DNS lookups work again", "zone", key, "after", dur.Round(time.Second).String())
	}
}

// rooted returns name as an absolute (rooted) name, so the resolver never
// appends search domains (Kubernetes pods use ndots:5).
func rooted(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}
