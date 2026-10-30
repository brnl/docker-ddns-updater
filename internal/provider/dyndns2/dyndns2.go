// Package dyndns2 implements the dyndns2 update protocol shared by many DDNS
// providers:
//
//	GET <endpoint>?hostname=<hostname>&myip=<ip>  (HTTP Basic authentication)
//
// Providers differ in how they take IPv6 addresses and in how a client must
// react to errors; Config captures those differences.
package dyndns2

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

const maxBodySize = 4096

// Config describes one dyndns2 provider.
type Config struct {
	// Name is the provider id used in logs and metrics, e.g. "mijnhost".
	Name string
	// DisplayName is used in error messages, e.g. "mijn.host".
	DisplayName string
	Endpoint    string
	Username    string
	Password    string
	UserAgent   string
	Timeout     time.Duration
	// SetIPs adds the address parameters for req to q.
	SetIPs func(q url.Values, req provider.Request)
	// StopOnRejection makes rejections (bad credentials, unknown hostname,
	// blocked client, ...) stop all further updates until the configuration
	// is fixed, as some providers require. Otherwise they are retried after
	// a long backoff.
	StopOnRejection bool
	// ServerErrorRetryAfter is the minimum wait after a server error (911,
	// dnserr, HTTP 5xx); zero uses the normal backoff.
	ServerErrorRetryAfter time.Duration
}

// SeparateIPv6 sends IPv4 as myip and IPv6 as myipv6.
func SeparateIPv6(q url.Values, req provider.Request) {
	if req.IPv4.IsValid() {
		q.Set("myip", req.IPv4.String())
	}
	if req.IPv6.IsValid() {
		q.Set("myipv6", req.IPv6.String())
	}
}

// CombinedIPs sends all addresses comma-separated in myip ("v4,v6").
func CombinedIPs(q url.Values, req provider.Request) {
	var ips []string
	if req.IPv4.IsValid() {
		ips = append(ips, req.IPv4.String())
	}
	if req.IPv6.IsValid() {
		ips = append(ips, req.IPv6.String())
	}
	q.Set("myip", strings.Join(ips, ","))
}

// Client is a provider.Provider for a dyndns2 service.
type Client struct {
	cfg    Config
	client *http.Client
}

// New returns a client for cfg.
func New(cfg Config) *Client {
	if cfg.SetIPs == nil {
		cfg.SetIPs = SeparateIPv6
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{
		cfg: cfg,
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Never follow redirects: credentials must only go to the endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) Name() string { return c.cfg.Name }

// Update sets the record(s) for req.Hostname. Only the address families that
// are set in req are sent.
func (c *Client) Update(ctx context.Context, req provider.Request) (string, error) {
	if !req.IPv4.IsValid() && !req.IPv6.IsValid() {
		// Omitting the address would make the provider use the request's
		// source address, which is never what we want here.
		return "", errors.New("no address to update")
	}
	u, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint: %w", err)
	}
	q := url.Values{}
	q.Set("hostname", req.Hostname)
	c.cfg.SetIPs(q, req)
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	// Credentials go in the Authorization header rather than the URL, so they
	// never end up in logged URLs or error messages.
	httpReq.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	httpReq.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", redactURLError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	text := firstLine(string(body))
	if err := c.interpret(resp.StatusCode, text); err != nil {
		return "", err
	}
	return truncate(text, 100), nil
}

// rejections maps dyndns2 error codes that need user intervention to a
// human-readable explanation.
var rejections = map[string]string{
	"badauth":  "invalid username or password",
	"nohost":   "hostname does not exist in this account",
	"notfqdn":  "hostname is not a fully qualified domain name",
	"numhost":  "too many hostnames in one request",
	"!yours":   "hostname is not owned by this account",
	"!donator": "feature not available for this account",
	"badagent": "client blocked (User-Agent rejected)",
	"abuse":    "account or client blocked for abuse",
	"badsys":   "invalid system parameter",
}

// interpret maps a dyndns2 response to an error.
func (c *Client) interpret(status int, text string) error {
	name := c.cfg.DisplayName
	code := ""
	if fields := strings.Fields(text); len(fields) > 0 {
		code = strings.ToLower(fields[0])
	}
	if code == "good" || code == "nochg" {
		if status >= 200 && status < 300 {
			return nil
		}
	}
	if why, ok := rejections[code]; ok {
		return c.rejected(fmt.Errorf("%s rejected the update: %s (%s)", name, code, why))
	}
	switch {
	case code == "dnserr" || code == "911":
		return c.serverError(fmt.Errorf("%s server error: %s", name, code))
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return c.rejected(fmt.Errorf("%s rejected the credentials (HTTP %d)", name, status))
	case status == http.StatusNotFound:
		return c.rejected(fmt.Errorf("%s: hostname not found (HTTP %d)", name, status))
	case status >= 500:
		return c.serverError(fmt.Errorf("%s server error (HTTP %d): %q", name, status, truncate(text, 200)))
	}
	return fmt.Errorf("unexpected response from %s (HTTP %d): %q", name, status, truncate(text, 200))
}

func (c *Client) rejected(err error) error {
	return &provider.PermanentError{Err: err, Stop: c.cfg.StopOnRejection}
}

func (c *Client) serverError(err error) error {
	if c.cfg.ServerErrorRetryAfter > 0 {
		return &provider.RetryAfterError{Err: err, After: c.cfg.ServerErrorRetryAfter}
	}
	return err
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
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
