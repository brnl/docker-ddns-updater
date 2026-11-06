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
)

const (
	// cacheTTL is how long discovered nameservers are reused.
	cacheTTL = time.Hour
	// negativeTTL is how long a failed discovery is remembered before
	// trying again (the fallback resolver is used meanwhile).
	negativeTTL = 15 * time.Minute
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
	// query performs the authoritative lookup; tests may replace it.
	query func(ctx context.Context, servers []string, network, host string) ([]netip.Addr, error)

	mu       sync.Mutex
	cache    map[string]*entry           // hostname -> nameservers
	fallback map[string]*condlog.Tracker // zone (or hostname) -> fallback state
}

type entry struct {
	zone        string
	nameservers []string // host names, for logs
	servers     []string // "ip:port" to query
	err         error
	expires     time.Time
}

// New returns a Resolver that discovers nameservers with, and falls back to,
// recursive.
func New(recursive Recursive, timeout time.Duration, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &Resolver{
		recursive: recursive,
		timeout:   timeout,
		log:       log,
		now:       time.Now,
		port:      "53",
		cache:     map[string]*entry{},
		fallback:  map[string]*condlog.Tracker{},
	}
	r.query = r.queryServers
	return r
}

// LookupNetIP looks up host's addresses ("ip4" or "ip6") at its zone's
// authoritative nameservers. A "not found" answer from them is returned as
// is; any other failure falls back to the recursive resolver.
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	e := r.nameservers(ctx, host)
	key := host
	if e.zone != "" {
		key = e.zone
	}
	if e.err == nil {
		addrs, err := r.query(ctx, e.servers, network, host)
		var dnsErr *net.DNSError
		if err == nil || (errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			r.recovered(key)
			return addrs, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
		r.failed(key, host, fmt.Errorf("querying %s: %w", strings.Join(e.nameservers, ", "), err))
	} else if ctx.Err() == nil {
		r.failed(key, host, e.err)
	}
	return r.recursive.LookupNetIP(ctx, network, rooted(host))
}

// nameservers returns the (cached) authoritative nameservers for host.
func (r *Resolver) nameservers(ctx context.Context, host string) *entry {
	now := r.now()
	r.mu.Lock()
	e, ok := r.cache[host]
	r.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e
	}
	e = r.discover(ctx, host)
	if ctx.Err() != nil {
		return e // do not cache a cancelled discovery
	}
	if e.err == nil {
		e.expires = now.Add(cacheTTL)
		if !ok || ok && !slices.Equal(e.nameservers, r.cachedNameservers(host)) {
			r.log.Info("checking DNS records at the authoritative nameservers",
				"hostname", host, "zone", e.zone, "nameservers", strings.Join(e.nameservers, ","))
		}
	} else {
		e.expires = now.Add(negativeTTL)
	}
	r.mu.Lock()
	r.cache[host] = e
	r.mu.Unlock()
	return e
}

func (r *Resolver) cachedNameservers(host string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[host]; ok {
		return e.nameservers
	}
	return nil
}

// discover walks up from host ("a.b.example.com", "b.example.com",
// "example.com") to the closest name with NS records: the zone apex. The
// top-level domain is never used: its servers only delegate.
func (r *Resolver) discover(ctx context.Context, host string) *entry {
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
			return &entry{zone: zone, err: fmt.Errorf("looking up the nameservers of %s: %w", zone, err)}
		}
		if len(ns) == 0 {
			continue
		}
		e := &entry{zone: zone}
		var v4, v6 []string
		for _, n := range ns {
			name := strings.TrimSuffix(n.Host, ".")
			e.nameservers = append(e.nameservers, name)
			addrs, err := r.recursive.LookupNetIP(ctx, "ip", rooted(name))
			if err != nil {
				continue
			}
			for _, a := range addrs {
				a = a.Unmap()
				hp := net.JoinHostPort(a.String(), r.port)
				if a.Is4() {
					v4 = append(v4, hp)
				} else {
					v6 = append(v6, hp)
				}
			}
		}
		slices.Sort(e.nameservers)
		// IPv4 first: IPv6 egress is often unavailable in containers.
		e.servers = append(v4, v6...)
		if len(e.servers) == 0 {
			e.err = fmt.Errorf("no address found for the nameservers of %s (%s)", zone, strings.Join(e.nameservers, ", "))
		}
		return e
	}
	return &entry{err: fmt.Errorf("no nameservers found for %s", host)}
}

// queryServers asks the given nameservers (in order, until one answers).
func (r *Resolver) queryServers(ctx context.Context, servers []string, network, host string) ([]netip.Addr, error) {
	dialer := &net.Dialer{Timeout: r.timeout}
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, proto, _ string) (net.Conn, error) {
			var errs []error
			for _, s := range servers {
				c, err := dialer.DialContext(ctx, proto, s)
				if err == nil {
					return c, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
	addrs, err := res.LookupNetIP(ctx, network, rooted(host))
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		// The Go resolver names the server from /etc/resolv.conf here,
		// which was not queried.
		dnsErr.Server = strings.Join(servers, ",")
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
