package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func base() map[string]string {
	return map[string]string{
		"DDNS_HOSTNAMES": "home.example.com",
		"DDNS_USERNAME":  "user",
		"DDNS_PASSWORD":  "pass",
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load(lookup(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Provider != "mijnhost" || c.Interval != time.Minute || !c.IPv4Enabled || c.IPv6Enabled {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if len(c.IPv4Sources) != 2 || c.ListenAddr != ":8080" || !c.StatusPage || !c.Metrics || c.DNSRecheckInterval != 5*time.Minute {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

func TestParsing(t *testing.T) {
	env := base()
	env["DDNS_HOSTNAMES"] = "a.example.com, b.example.com\n*.example.org"
	env["DDNS_INTERVAL"] = "30"
	env["DDNS_DNS_RECHECK_INTERVAL"] = "1m"
	env["DDNS_IPV6_ENABLED"] = "true"
	env["DDNS_IPV4_ENABLED"] = "false"
	c, err := Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Hostnames, "|"); got != "a.example.com|b.example.com|*.example.org" {
		t.Errorf("hostnames = %q", got)
	}
	if c.Interval != 30*time.Second || c.DNSRecheckInterval != time.Minute || c.IPv4Enabled || !c.IPv6Enabled {
		t.Errorf("unexpected config: %+v", c)
	}
}

func TestSecretFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := base()
	delete(env, "DDNS_PASSWORD")
	env["DDNS_PASSWORD_FILE"] = path
	c, err := Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if c.Password != "s3cr3t" {
		t.Errorf("password = %q", c.Password)
	}

	env["DDNS_PASSWORD"] = "also"
	if _, err := Load(lookup(env)); err == nil {
		t.Error("expected error when both DDNS_PASSWORD and DDNS_PASSWORD_FILE are set")
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]map[string]string{
		"no hostnames":   {"DDNS_HOSTNAMES": ""},
		"bad hostname":   {"DDNS_HOSTNAMES": "not a host!"},
		"single label":   {"DDNS_HOSTNAMES": "localhost"},
		"no username":    {"DDNS_USERNAME": ""},
		"no families":    {"DDNS_IPV4_ENABLED": "false"},
		"bad bool":       {"DDNS_IPV6_ENABLED": "maybe"},
		"bad interval":   {"DDNS_INTERVAL": "soon"},
		"tiny interval":  {"DDNS_INTERVAL": "100ms"},
		"bad provider":   {"DDNS_PROVIDER": "nope"},
		"bad source":     {"DDNS_IPV4_SOURCES": "ftp://example.com"},
		"bad log level":  {"DDNS_LOG_LEVEL": "loud"},
		"bad log format": {"DDNS_LOG_FORMAT": "xml"},
		"bad dns server": {"DDNS_DNS_SERVER": "not a server!"},
		"bad dns port":   {"DDNS_DNS_SERVER": "1.1.1.1:99999"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			env := base()
			for k, v := range overrides {
				env[k] = v
			}
			if _, err := Load(lookup(env)); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestNormalizeDNSServer(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                    "1.1.1.1:53",
		"1.1.1.1:5353":               "1.1.1.1:5353",
		"2606:4700:4700::1111":       "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]":     "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]:853": "[2606:4700:4700::1111]:853",
		"dns.example.net":            "dns.example.net:53",
		"dns.example.net:5353":       "dns.example.net:5353",
	}
	for in, want := range cases {
		got, err := NormalizeDNSServer(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDNSServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"bad host!", "1.1.1.1:0", "dns.example.net:x", "host:53:53"} {
		if got, err := NormalizeDNSServer(bad); err == nil {
			t.Errorf("NormalizeDNSServer(%q) = %q, want error", bad, got)
		}
	}
}
