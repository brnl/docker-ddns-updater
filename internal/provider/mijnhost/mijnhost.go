// Package mijnhost implements the mijn.host DynDNS (dyndns2 compatible) API:
//
//	https://<username>:<password>@mijn.host/nic/update?hostname=<hostname>&myip=<ipv4>&myipv6=<ipv6>
package mijnhost

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/provider"
)

// DefaultEndpoint is the mijn.host DynDNS update URL.
const DefaultEndpoint = "https://mijn.host/nic/update"

const maxBodySize = 4096

// Provider updates records via the mijn.host DynDNS API.
type Provider struct {
	endpoint  string
	username  string
	password  string
	userAgent string
	client    *http.Client
}

// New returns a mijn.host provider. An empty endpoint uses DefaultEndpoint.
func New(endpoint, username, password, userAgent string, timeout time.Duration) *Provider {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Provider{
		endpoint:  endpoint,
		username:  username,
		password:  password,
		userAgent: userAgent,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			// Never follow redirects: credentials must only go to the endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (p *Provider) Name() string { return "mijnhost" }

// Update sets the record(s) for req.Hostname. Only the address families that
// are set in req are sent.
func (p *Provider) Update(ctx context.Context, req provider.Request) error {
	if !req.IPv4.IsValid() && !req.IPv6.IsValid() {
		// Omitting both would make mijn.host use the request's source address,
		// which is never what we want here.
		return errors.New("no address to update")
	}
	u, err := url.Parse(p.endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}
	q := url.Values{}
	q.Set("hostname", req.Hostname)
	if req.IPv4.IsValid() {
		q.Set("myip", req.IPv4.String())
	}
	if req.IPv6.IsValid() {
		q.Set("myipv6", req.IPv6.String())
	}
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	// Credentials go in the Authorization header rather than the URL, so they
	// never end up in logged URLs or error messages.
	httpReq.SetBasicAuth(p.username, p.password)
	httpReq.Header.Set("User-Agent", p.userAgent)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", redactURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	return interpret(resp.StatusCode, string(body))
}

// interpret maps a dyndns2 style response to an error.
func interpret(status int, body string) error {
	text := strings.TrimSpace(body)
	code := ""
	if fields := strings.Fields(text); len(fields) > 0 {
		code = strings.ToLower(fields[0])
	}
	switch code {
	case "good", "nochg":
		if status >= 200 && status < 300 {
			return nil
		}
	case "badauth", "!donator", "notfqdn", "nohost", "numhost", "abuse", "badagent", "!yours", "badsys":
		return &provider.PermanentError{Err: fmt.Errorf("mijn.host rejected the update: %s", code)}
	case "dnserr", "911":
		return fmt.Errorf("mijn.host temporary server error: %s", code)
	}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &provider.PermanentError{Err: fmt.Errorf("mijn.host rejected the credentials (HTTP %d)", status)}
	case status == http.StatusNotFound:
		return &provider.PermanentError{Err: fmt.Errorf("mijn.host: hostname not found (HTTP %d)", status)}
	}
	return fmt.Errorf("unexpected response from mijn.host (HTTP %d): %q", status, truncate(text, 200))
}

// redactURLError strips the URL from a *url.Error; it holds no credentials
// but keeps log lines short and consistent.
func redactURLError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err
	}
	return err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
