// Package config loads the updater configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Default public IP sources. Each source must return the caller's IP address
// as plain text.
var (
	DefaultIPv4Sources = []string{"https://api.ipify.org", "https://ifconfig.me/ip"}
	DefaultIPv6Sources = []string{"https://api6.ipify.org", "https://ifconfig.me/ip"}
)

// Providers lists the supported DDNS providers.
var Providers = []string{"mijnhost", "noip"}

// DefaultAccount is the name of the account configured with the top-level
// DDNS_PROVIDER/DDNS_HOSTNAMES/DDNS_USERNAME/DDNS_PASSWORD variables.
const DefaultAccount = "default"

// Account is one set of provider credentials and the hostnames it updates.
type Account struct {
	// Name identifies the account in logs, metrics and the status page.
	Name      string
	Provider  string
	Hostnames []string
	Username  string
	Password  string
	// Endpoint overrides the provider's update URL (testing); usually empty.
	Endpoint string
}

// Config holds the runtime configuration.
type Config struct {
	// Accounts holds at least one account; every hostname belongs to
	// exactly one of them.
	Accounts []Account
	// ContactEmail is sent in the User-Agent, as No-IP recommends.
	ContactEmail string

	IPv4Enabled bool
	IPv6Enabled bool
	IPv4Sources []string
	IPv6Sources []string

	Interval           time.Duration
	Timeout            time.Duration
	DNSRecheckInterval time.Duration
	DNSServer          string
	Heartbeat          time.Duration

	DryRun     bool
	ListenAddr string
	StatusPage bool
	Metrics    bool
	LogLevel   string
	LogFormat  string
}

// Load reads the configuration from the given lookup function (normally
// os.LookupEnv).
func Load(lookup func(string) (string, bool)) (*Config, error) {
	e := env{lookup: lookup}
	c := &Config{
		Accounts:           loadAccounts(&e),
		ContactEmail:       e.str("DDNS_CONTACT_EMAIL", ""),
		IPv4Enabled:        e.bool("DDNS_IPV4_ENABLED", true),
		IPv6Enabled:        e.bool("DDNS_IPV6_ENABLED", false),
		IPv4Sources:        e.list("DDNS_IPV4_SOURCES", DefaultIPv4Sources),
		IPv6Sources:        e.list("DDNS_IPV6_SOURCES", DefaultIPv6Sources),
		Interval:           e.duration("DDNS_INTERVAL", time.Minute),
		Timeout:            e.duration("DDNS_TIMEOUT", 10*time.Second),
		DNSRecheckInterval: e.duration("DDNS_DNS_RECHECK_INTERVAL", 5*time.Minute),
		DNSServer:          e.str("DDNS_DNS_SERVER", ""),
		Heartbeat:          e.duration("DDNS_HEARTBEAT_INTERVAL", time.Hour),
		DryRun:             e.bool("DDNS_DRY_RUN", false),
		ListenAddr:         e.str("DDNS_LISTEN_ADDR", ":8080"),
		StatusPage:         e.bool("DDNS_STATUS_PAGE", true),
		Metrics:            e.bool("DDNS_METRICS", true),
		LogLevel:           strings.ToLower(e.str("DDNS_LOG_LEVEL", "info")),
		LogFormat:          strings.ToLower(e.str("DDNS_LOG_FORMAT", "json")),
	}
	if len(e.errs) > 0 {
		return nil, errors.Join(e.errs...)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	errs := c.validateAccounts()
	if !c.IPv4Enabled && !c.IPv6Enabled {
		errs = append(errs, errors.New("at least one of DDNS_IPV4_ENABLED or DDNS_IPV6_ENABLED must be true"))
	}
	if c.IPv4Enabled {
		errs = append(errs, validateSources("DDNS_IPV4_SOURCES", c.IPv4Sources)...)
	}
	if c.IPv6Enabled {
		errs = append(errs, validateSources("DDNS_IPV6_SOURCES", c.IPv6Sources)...)
	}
	if c.Interval < time.Second {
		errs = append(errs, errors.New("DDNS_INTERVAL must be at least 1s"))
	}
	if c.Timeout <= 0 {
		errs = append(errs, errors.New("DDNS_TIMEOUT must be positive"))
	}
	if c.DNSServer != "" {
		addr, err := NormalizeDNSServer(c.DNSServer)
		if err != nil {
			errs = append(errs, fmt.Errorf("DDNS_DNS_SERVER: %w", err))
		}
		c.DNSServer = addr
	}
	if c.ContactEmail != "" && !validEmail(c.ContactEmail) {
		errs = append(errs, fmt.Errorf("DDNS_CONTACT_EMAIL: invalid e-mail address %q", c.ContactEmail))
	}
	if c.Heartbeat < 0 {
		errs = append(errs, errors.New("DDNS_HEARTBEAT_INTERVAL must not be negative"))
	}
	if c.DNSRecheckInterval < 0 {
		errs = append(errs, errors.New("DDNS_DNS_RECHECK_INTERVAL must not be negative"))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("DDNS_LOG_LEVEL: invalid level %q", c.LogLevel))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("DDNS_LOG_FORMAT: invalid format %q", c.LogFormat))
	}
	return errors.Join(errs...)
}

// NormalizeDNSServer turns a DNS server given as an IP address or hostname,
// with an optional port, into a host:port dial address (default port 53).
// Accepted: "1.1.1.1", "1.1.1.1:5353", "2606:4700:4700::1111",
// "[2606:4700:4700::1111]:53", "dns.example.net", "dns.example.net:53".
func NormalizeDNSServer(s string) (string, error) {
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else if _, perr := netip.ParseAddr(strings.Trim(s, "[]")); perr == nil {
		host = strings.Trim(s, "[]") // bare IPv6 address without port
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port in %q", s)
	}
	if _, err := netip.ParseAddr(host); err != nil && !validHostname(host) && host != "localhost" {
		return "", fmt.Errorf("%q is not an IP address or hostname", s)
	}
	return net.JoinHostPort(host, port), nil
}

// validEmail is a deliberately simple check: local@domain, no whitespace or
// control characters (the value goes into an HTTP header).
func validEmail(s string) bool {
	if len(s) > 254 || strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && !strings.Contains(domain, "@") && validHostname(domain)
}

// accountPrefix returns the environment variable prefix of an account:
// "DDNS_" for the default account, "DDNS_ACCOUNT_<NAME>_" otherwise.
func accountPrefix(name string) string {
	if name == DefaultAccount {
		return "DDNS_"
	}
	return "DDNS_ACCOUNT_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// loadAccounts reads the default account (if DDNS_HOSTNAMES is set, or no
// DDNS_ACCOUNTS are listed) and every account named in DDNS_ACCOUNTS.
func loadAccounts(e *env) []Account {
	names := e.list("DDNS_ACCOUNTS", nil)
	if e.str("DDNS_HOSTNAMES", "") != "" || len(names) == 0 {
		names = append([]string{DefaultAccount}, names...)
	}
	accounts := make([]Account, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(name)
		p := accountPrefix(name)
		// Only the default account falls back to mijnhost (its historic
		// default); other accounts must name their provider, so credentials
		// never go to a provider by accident.
		defaultProvider := ""
		if name == DefaultAccount {
			defaultProvider = "mijnhost"
		}
		a := Account{
			Name:      name,
			Provider:  strings.ToLower(e.str(p+"PROVIDER", defaultProvider)),
			Hostnames: e.list(p+"HOSTNAMES", nil),
			Username:  e.secret(p + "USERNAME"),
			Password:  e.secret(p + "PASSWORD"),
			Endpoint:  e.str(p+"ENDPOINT", ""),
		}
		if name == DefaultAccount && a.Endpoint == "" && a.Provider == "mijnhost" {
			// Older name, only ever meant for mijn.host.
			a.Endpoint = e.str("DDNS_MIJNHOST_ENDPOINT", "")
		}
		accounts = append(accounts, a)
	}
	return accounts
}

func (c *Config) validateAccounts() []error {
	var errs []error
	if len(c.Accounts) == 0 {
		errs = append(errs, errors.New("no accounts configured: set DDNS_HOSTNAMES or DDNS_ACCOUNTS"))
	}
	names := map[string]bool{}
	owner := map[string]string{} // hostname -> account
	for i := range c.Accounts {
		a := &c.Accounts[i]
		p := accountPrefix(a.Name)
		if !validAccountName(a.Name) {
			errs = append(errs, fmt.Errorf("DDNS_ACCOUNTS: invalid account name %q (use a-z, 0-9 and -, max 32 characters)", a.Name))
			continue
		}
		if names[a.Name] {
			errs = append(errs, fmt.Errorf("DDNS_ACCOUNTS: account %q is listed twice", a.Name))
			continue
		}
		names[a.Name] = true
		if a.Provider == "" {
			errs = append(errs, fmt.Errorf("%sPROVIDER is required (supported: %s)", p, strings.Join(Providers, ", ")))
		} else if !slices.Contains(Providers, a.Provider) {
			errs = append(errs, fmt.Errorf("%sPROVIDER: unsupported provider %q (supported: %s)", p, a.Provider, strings.Join(Providers, ", ")))
		}
		if len(a.Hostnames) == 0 {
			errs = append(errs, fmt.Errorf("%sHOSTNAMES: at least one hostname is required", p))
		}
		var unique []string
		for _, h := range a.Hostnames {
			if !validHostname(h) {
				errs = append(errs, fmt.Errorf("%sHOSTNAMES: invalid hostname %q", p, h))
				continue
			}
			key := strings.ToLower(strings.TrimSuffix(h, "."))
			switch other, dup := owner[key]; {
			case !dup:
				owner[key] = a.Name
				unique = append(unique, h)
			case other != a.Name:
				errs = append(errs, fmt.Errorf("%sHOSTNAMES: hostname %q is also configured for account %q; each hostname must belong to one account", p, h, other))
			}
			// A repeat within the same account is dropped, as before.
		}
		a.Hostnames = unique
		if a.Username == "" {
			errs = append(errs, fmt.Errorf("%sUSERNAME (or %sUSERNAME_FILE) is required", p, p))
		}
		if a.Password == "" {
			errs = append(errs, fmt.Errorf("%sPASSWORD (or %sPASSWORD_FILE) is required", p, p))
		}
		if a.Endpoint != "" {
			if u, err := url.Parse(a.Endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
				errs = append(errs, fmt.Errorf("%sENDPOINT: invalid URL (must be http(s) without credentials)", p))
			}
		}
	}
	return errs
}

// Hostnames returns every configured hostname, in account order.
func (c *Config) Hostnames() []string {
	var out []string
	for _, a := range c.Accounts {
		out = append(out, a.Hostnames...)
	}
	return out
}

func validAccountName(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validateSources(name string, sources []string) []error {
	if len(sources) == 0 {
		return []error{fmt.Errorf("%s: at least one source is required", name)}
	}
	var errs []error
	for _, s := range sources {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			errs = append(errs, fmt.Errorf("%s: invalid URL %q", name, s))
		}
	}
	return errs
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for i, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return false
		}
		// Allow a leading wildcard label.
		if l == "*" && i == 0 {
			continue
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

type env struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (e *env) str(key, def string) string {
	if v, ok := e.lookup(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func (e *env) list(key string, def []string) []string {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (e *env) bool(key string, def bool) bool {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid boolean %q", key, v))
		return def
	}
	return b
}

// duration accepts Go duration strings ("10s", "5m") or a plain number of
// seconds ("10").
func (e *env) duration(key string, def time.Duration) time.Duration {
	v := e.str(key, "")
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(n) * time.Second
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: invalid duration %q", key, v))
		return def
	}
	return d
}

// secret reads KEY, or the contents of the file named by KEY_FILE. Setting
// both is an error.
func (e *env) secret(key string) string {
	v := e.str(key, "")
	file := e.str(key+"_FILE", "")
	if v != "" && file != "" {
		e.errs = append(e.errs, fmt.Errorf("only one of %s and %s_FILE may be set", key, key))
		return ""
	}
	if file == "" {
		return v
	}
	b, err := os.ReadFile(file)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s_FILE: %w", key, err))
		return ""
	}
	return strings.TrimRight(string(b), "\r\n")
}
