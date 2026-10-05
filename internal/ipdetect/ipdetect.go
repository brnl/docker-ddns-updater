// Package ipdetect determines the public IPv4/IPv6 address by querying
// plain-text "what is my IP" services.
package ipdetect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Family is an IP address family.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func (f Family) String() string {
	if f == IPv6 {
		return "ipv6"
	}
	return "ipv4"
}

func (f Family) network() string {
	if f == IPv6 {
		return "tcp6"
	}
	return "tcp4"
}

// maxBodySize bounds how much of a source response is read.
const maxBodySize = 256

// Detector queries a set of sources for the public address of one family.
type Detector struct {
	family    Family
	sources   []string
	client    *http.Client
	userAgent string
}

// New returns a Detector that only connects over the given address family,
// so each source reports the address of that family.
func New(family Family, sources []string, timeout time.Duration, userAgent string) *Detector {
	dialer := &net.Dialer{Timeout: timeout}
	network := family.network()
	transport := &http.Transport{
		// Never use a proxy: the source would see the proxy's address.
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		// A fresh connection per check, so an address change is never hidden
		// behind (or stalled by) a connection opened from the old address.
		DisableKeepAlives: true,
	}
	return &Detector{
		family:    family,
		sources:   sources,
		client:    &http.Client{Transport: transport, Timeout: timeout},
		userAgent: userAgent,
	}
}

// Family returns the address family this detector reports.
func (d *Detector) Family() Family { return d.family }

// Detect queries all sources concurrently. It succeeds when at least one
// source answers and all answering sources agree; if sources disagree, no
// address is returned so that a single faulty or malicious source cannot
// redirect the DNS record.
func (d *Detector) Detect(ctx context.Context) (netip.Addr, error) {
	type result struct {
		source string
		addr   netip.Addr
		err    error
	}
	results := make([]result, len(d.sources))
	var wg sync.WaitGroup
	for i, src := range d.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := d.query(ctx, src)
			results[i] = result{source: src, addr: addr, err: err}
		}()
	}
	wg.Wait()

	var (
		found netip.Addr
		errs  []error
	)
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.source, r.err))
			continue
		}
		if found.IsValid() && found != r.addr {
			return netip.Addr{}, fmt.Errorf("sources disagree on %s address: %s vs %s", d.family, found, r.addr)
		}
		found = r.addr
	}
	if !found.IsValid() {
		return netip.Addr{}, fmt.Errorf("no source returned a valid %s address: %w", d.family, errors.Join(errs...))
	}
	return found, nil
}

func (d *Detector) query(ctx context.Context, src string) (netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "text/plain")
	resp, err := d.client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return netip.Addr{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return Parse(d.family, string(body))
}

// Parse parses and validates a public address of the given family.
func Parse(family Family, s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", truncate(s, 64))
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("unexpected zone in address %q", s)
	}
	switch family {
	case IPv4:
		addr = addr.Unmap()
		if !addr.Is4() {
			return netip.Addr{}, fmt.Errorf("%s is not an IPv4 address", addr)
		}
	case IPv6:
		if !addr.Is6() || addr.Is4In6() {
			return netip.Addr{}, fmt.Errorf("%s is not an IPv6 address", addr)
		}
	}
	if !IsPublic(addr) {
		return netip.Addr{}, fmt.Errorf("%s is not a public address", addr)
	}
	return addr, nil
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// IsPublic reports whether addr is a globally routable unicast address.
func IsPublic(addr netip.Addr) bool {
	return addr.IsGlobalUnicast() && !addr.IsPrivate() && !sharedAddressSpace.Contains(addr)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
