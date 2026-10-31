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
	if len(c.Accounts) != 1 || c.Accounts[0].Name != "default" || c.Accounts[0].Provider != "mijnhost" || c.Interval != time.Minute || !c.IPv4Enabled || c.IPv6Enabled {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if len(c.IPv4Sources) != 2 || c.ListenAddr != ":8080" || !c.StatusPage || !c.Metrics || c.DNSRecheckInterval != 5*time.Minute || c.Heartbeat != time.Hour {
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
	if got := strings.Join(c.Hostnames(), "|"); got != "a.example.com|b.example.com|*.example.org" {
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
	if c.Accounts[0].Password != "s3cr3t" {
		t.Errorf("password = %q", c.Accounts[0].Password)
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
		"bad heartbeat":  {"DDNS_HEARTBEAT_INTERVAL": "-1m"},
		"bad contact":    {"DDNS_CONTACT_EMAIL": "not-an-email"},
		"contact header": {"DDNS_CONTACT_EMAIL": "a@example.com\r\nX-Evil: 1"},
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

func TestProviders(t *testing.T) {
	for _, p := range []string{"mijnhost", "noip", "NoIP"} {
		env := base()
		env["DDNS_PROVIDER"] = p
		c, err := Load(lookup(env))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if c.Accounts[0].Provider != strings.ToLower(p) {
			t.Errorf("provider = %q", c.Accounts[0].Provider)
		}
	}
}

func TestContactEmail(t *testing.T) {
	env := base()
	env["DDNS_CONTACT_EMAIL"] = "me@example.com"
	c, err := Load(lookup(env))
	if err != nil || c.ContactEmail != "me@example.com" {
		t.Fatalf("ContactEmail = %q, %v", c.ContactEmail, err)
	}
}

func TestMultipleAccounts(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte("work-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"DDNS_ACCOUNTS":                     "home, work-2",
		"DDNS_ACCOUNT_HOME_PROVIDER":        "noip",
		"DDNS_ACCOUNT_HOME_HOSTNAMES":       "a.ddns.net",
		"DDNS_ACCOUNT_HOME_USERNAME":        "me@example.com",
		"DDNS_ACCOUNT_HOME_PASSWORD":        "home-secret",
		"DDNS_ACCOUNT_WORK_2_HOSTNAMES":     "b.example.nl,c.example.nl",
		"DDNS_ACCOUNT_WORK_2_USERNAME":      "work",
		"DDNS_ACCOUNT_WORK_2_PASSWORD_FILE": pw,
		"DDNS_ACCOUNT_WORK_2_ENDPOINT":      "https://proxy.example.nl/nic/update",
	}
	c, err := Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Accounts) != 2 {
		t.Fatalf("accounts = %+v", c.Accounts)
	}
	home, work := c.Accounts[0], c.Accounts[1]
	if home.Name != "home" || home.Provider != "noip" || home.Password != "home-secret" || strings.Join(home.Hostnames, ",") != "a.ddns.net" {
		t.Errorf("home = %+v", home)
	}
	if work.Name != "work-2" || work.Provider != "mijnhost" || work.Password != "work-secret" || work.Endpoint != "https://proxy.example.nl/nic/update" || len(work.Hostnames) != 2 {
		t.Errorf("work = %+v", work)
	}
	if got := strings.Join(c.Hostnames(), ","); got != "a.ddns.net,b.example.nl,c.example.nl" {
		t.Errorf("hostnames = %q", got)
	}
}

func TestDefaultPlusAccounts(t *testing.T) {
	env := base()
	env["DDNS_ACCOUNTS"] = "extra"
	env["DDNS_ACCOUNT_EXTRA_PROVIDER"] = "noip"
	env["DDNS_ACCOUNT_EXTRA_HOSTNAMES"] = "x.ddns.net"
	env["DDNS_ACCOUNT_EXTRA_USERNAME"] = "u"
	env["DDNS_ACCOUNT_EXTRA_PASSWORD"] = "p"
	c, err := Load(lookup(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Accounts) != 2 || c.Accounts[0].Name != "default" || c.Accounts[1].Name != "extra" {
		t.Fatalf("accounts = %+v", c.Accounts)
	}
}

func TestLegacyEndpointOnlyForMijnhost(t *testing.T) {
	env := base()
	env["DDNS_MIJNHOST_ENDPOINT"] = "https://legacy.example/nic/update"
	c, _ := Load(lookup(env))
	if c.Accounts[0].Endpoint != "https://legacy.example/nic/update" {
		t.Errorf("mijnhost endpoint = %q", c.Accounts[0].Endpoint)
	}
	env["DDNS_PROVIDER"] = "noip"
	c, _ = Load(lookup(env))
	if c.Accounts[0].Endpoint != "" {
		t.Errorf("legacy mijn.host endpoint used for noip: %q", c.Accounts[0].Endpoint)
	}
}

func TestInvalidAccounts(t *testing.T) {
	acct := func(extra map[string]string) map[string]string {
		env := map[string]string{
			"DDNS_ACCOUNTS":            "a",
			"DDNS_ACCOUNT_A_HOSTNAMES": "a.example.com",
			"DDNS_ACCOUNT_A_USERNAME":  "u",
			"DDNS_ACCOUNT_A_PASSWORD":  "p",
		}
		for k, v := range extra {
			env[k] = v
		}
		return env
	}
	if _, err := Load(lookup(acct(nil))); err != nil {
		t.Fatalf("valid account rejected: %v", err)
	}
	cases := map[string]map[string]string{
		"no accounts at all":  {"DDNS_ACCOUNTS": ""},
		"bad name":            {"DDNS_ACCOUNTS": "Bad_Name!"},
		"duplicate name":      {"DDNS_ACCOUNTS": "a,a"},
		"missing password":    {"DDNS_ACCOUNT_A_PASSWORD": ""},
		"bad provider":        {"DDNS_ACCOUNT_A_PROVIDER": "dyndns"},
		"no hostnames":        {"DDNS_ACCOUNT_A_HOSTNAMES": ""},
		"endpoint with creds": {"DDNS_ACCOUNT_A_ENDPOINT": "https://u:p@example.com/nic/update"},
		"endpoint not http":   {"DDNS_ACCOUNT_A_ENDPOINT": "ftp://example.com"},
		"hostname in two accounts": {
			"DDNS_ACCOUNTS": "a,b", "DDNS_ACCOUNT_B_HOSTNAMES": "A.example.com.",
			"DDNS_ACCOUNT_B_USERNAME": "u", "DDNS_ACCOUNT_B_PASSWORD": "p",
		},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			env := acct(extra)
			for k, v := range extra {
				if v == "" {
					delete(env, k)
				}
			}
			if _, err := Load(lookup(env)); err == nil {
				t.Error("expected error")
			}
		})
	}
}
