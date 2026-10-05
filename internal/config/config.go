// Package config loads the updater configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
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

// Config holds the runtime configuration.
type Config struct {
	Provider  string
	Hostnames []string
	Username  string
	Password  string

	IPv4Enabled bool
	IPv6Enabled bool
	IPv4Sources []string
	IPv6Sources []string

	Interval           time.Duration
	Timeout            time.Duration
	DNSRecheckInterval time.Duration
	DNSServer          string

	DryRun     bool
	ListenAddr string
	StatusPage bool
	LogLevel   string
	LogFormat  string
}

// Load reads the configuration from the given lookup function (normally
// os.LookupEnv).
func Load(lookup func(string) (string, bool)) (*Config, error) {
	e := env{lookup: lookup}
	c := &Config{
		Provider:           strings.ToLower(e.str("DDNS_PROVIDER", "mijnhost")),
		Hostnames:          e.list("DDNS_HOSTNAMES", nil),
		Username:           e.secret("DDNS_USERNAME"),
		Password:           e.secret("DDNS_PASSWORD"),
		IPv4Enabled:        e.bool("DDNS_IPV4_ENABLED", true),
		IPv6Enabled:        e.bool("DDNS_IPV6_ENABLED", false),
		IPv4Sources:        e.list("DDNS_IPV4_SOURCES", DefaultIPv4Sources),
		IPv6Sources:        e.list("DDNS_IPV6_SOURCES", DefaultIPv6Sources),
		Interval:           e.duration("DDNS_INTERVAL", 10*time.Second),
		Timeout:            e.duration("DDNS_TIMEOUT", 10*time.Second),
		DNSRecheckInterval: e.duration("DDNS_DNS_RECHECK_INTERVAL", 5*time.Minute),
		DNSServer:          e.str("DDNS_DNS_SERVER", ""),
		DryRun:             e.bool("DDNS_DRY_RUN", false),
		ListenAddr:         e.str("DDNS_LISTEN_ADDR", ":8080"),
		StatusPage:         e.bool("DDNS_STATUS_PAGE", true),
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
	var errs []error
	switch c.Provider {
	case "mijnhost":
	default:
		errs = append(errs, fmt.Errorf("DDNS_PROVIDER: unsupported provider %q (supported: mijnhost)", c.Provider))
	}
	if len(c.Hostnames) == 0 {
		errs = append(errs, errors.New("DDNS_HOSTNAMES: at least one hostname is required"))
	}
	for _, h := range c.Hostnames {
		if !validHostname(h) {
			errs = append(errs, fmt.Errorf("DDNS_HOSTNAMES: invalid hostname %q", h))
		}
	}
	if c.Username == "" {
		errs = append(errs, errors.New("DDNS_USERNAME (or DDNS_USERNAME_FILE) is required"))
	}
	if c.Password == "" {
		errs = append(errs, errors.New("DDNS_PASSWORD (or DDNS_PASSWORD_FILE) is required"))
	}
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
