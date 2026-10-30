package dyndns2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/provider"
)

func TestInterpret(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		ok        bool
		permanent bool
	}{
		{200, "good 1.2.3.4", true, false},
		{200, "nochg 1.2.3.4", true, false},
		{200, "badauth", false, true},
		{200, "nohost", false, true},
		{200, "notfqdn", false, true},
		{200, "abuse", false, true},
		{200, "badagent", false, true},
		{200, "!donator", false, true},
		{200, "911", false, false},
		{200, "dnserr", false, false},
		{401, "", false, true},
		{500, "internal error", false, false},
		{200, "<html>surprise</html>", false, false},
		{500, "good 1.2.3.4", false, false},
	}
	for _, stop := range []bool{false, true} {
		c := New(Config{DisplayName: "Test", StopOnRejection: stop})
		for _, tc := range cases {
			err := c.interpret(tc.status, tc.body)
			if (err == nil) != tc.ok {
				t.Errorf("interpret(%d, %q) = %v, want ok=%v", tc.status, tc.body, err, tc.ok)
				continue
			}
			if err == nil {
				continue
			}
			if provider.IsPermanent(err) != tc.permanent {
				t.Errorf("interpret(%d, %q) permanent = %v, want %v", tc.status, tc.body, provider.IsPermanent(err), tc.permanent)
			}
			bare := tc.body == "" // bare HTTP status without dyndns2 code
			if provider.StopsUpdates(err) != (tc.permanent && stop && !bare) {
				t.Errorf("interpret(%d, %q) stop = %v with StopOnRejection=%v", tc.status, tc.body, provider.StopsUpdates(err), stop)
			}
		}
	}
	if err := New(Config{DisplayName: "Test"}).interpret(200, "badauth"); !strings.Contains(err.Error(), "invalid username or password") {
		t.Errorf("rejection lacks explanation: %v", err)
	}
}

func TestServerErrorRetryAfter(t *testing.T) {
	c := New(Config{DisplayName: "Test", ServerErrorRetryAfter: 30 * time.Minute})
	for _, tc := range []struct {
		status int
		body   string
	}{{200, "911"}, {500, "oops"}, {503, ""}} {
		after, ok := provider.RetryAfter(c.interpret(tc.status, tc.body))
		if !ok || after != 30*time.Minute {
			t.Errorf("interpret(%d, %q) retry after = %s, %v", tc.status, tc.body, after, ok)
		}
	}
	if _, ok := provider.RetryAfter(New(Config{}).interpret(200, "911")); ok {
		t.Error("retry-after set without ServerErrorRetryAfter")
	}
}

func TestSetIPs(t *testing.T) {
	v4, v6 := netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::1")
	cases := []struct {
		set  func(url.Values, provider.Request)
		req  provider.Request
		want string
	}{
		{SeparateIPv6, provider.Request{IPv4: v4, IPv6: v6}, "myip=203.0.113.7&myipv6=2001%3Adb8%3A%3A1"},
		{SeparateIPv6, provider.Request{IPv6: v6}, "myipv6=2001%3Adb8%3A%3A1"},
		{CombinedIPs, provider.Request{IPv4: v4, IPv6: v6}, "myip=203.0.113.7%2C2001%3Adb8%3A%3A1"},
		{CombinedIPs, provider.Request{IPv4: v4}, "myip=203.0.113.7"},
		{CombinedIPs, provider.Request{IPv6: v6}, "myip=2001%3Adb8%3A%3A1"},
	}
	for _, tc := range cases {
		q := url.Values{}
		tc.set(q, tc.req)
		if got := q.Encode(); got != tc.want {
			t.Errorf("got %s, want %s", got, tc.want)
		}
	}
}

func TestMultiLineResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("good 203.0.113.7\r\n"))
	}))
	defer srv.Close()
	c := New(Config{Endpoint: srv.URL, DisplayName: "Test", Timeout: time.Second})
	resp, err := c.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv4: netip.MustParseAddr("203.0.113.7")})
	if err != nil || resp != "good 203.0.113.7" {
		t.Fatalf("Update = %q, %v", resp, err)
	}
}

func TestAccountScope(t *testing.T) {
	c := New(Config{DisplayName: "Test", StopOnRejection: true})
	for code, account := range map[string]bool{"badauth": true, "badagent": true, "abuse": true, "nohost": false, "!donator": false} {
		if got := provider.StopsAllUpdates(c.interpret(200, code)); got != account {
			t.Errorf("%s: StopsAllUpdates = %v, want %v", code, got, account)
		}
	}
}

func TestBareHTTPErrorsNeverStop(t *testing.T) {
	c := New(Config{DisplayName: "Test", StopOnRejection: true})
	for _, status := range []int{401, 403, 404} {
		err := c.interpret(status, "<html>Access denied</html>")
		if !provider.IsPermanent(err) || provider.StopsUpdates(err) {
			t.Errorf("HTTP %d: permanent=%v stop=%v", status, provider.IsPermanent(err), provider.StopsUpdates(err))
		}
	}
}

func TestErrorsDoNotLeakCredentials(t *testing.T) {
	for _, body := range []string{"badauth", "911", "<html>oops</html>", ""} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(body))
		}))
		c := New(Config{Endpoint: srv.URL, DisplayName: "Test", Username: "user@example.com", Password: "p@ss:word", Timeout: time.Second})
		_, err := c.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv4: netip.MustParseAddr("203.0.113.7")})
		srv.Close()
		if err == nil || strings.Contains(err.Error(), "p@ss") || strings.Contains(err.Error(), "user@example.com") {
			t.Errorf("error leaks credentials or is nil: %v", err)
		}
	}
	// Connection errors must not include the URL with credentials either.
	c := New(Config{Endpoint: "http://127.0.0.1:1/nic/update", DisplayName: "Test", Username: "u", Password: "p@ss:word", Timeout: time.Second})
	_, err := c.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv4: netip.MustParseAddr("203.0.113.7")})
	if err == nil || strings.Contains(err.Error(), "p@ss") || strings.Contains(err.Error(), "127.0.0.1:1/nic") {
		t.Errorf("connection error leaks details: %v", err)
	}
}

func TestDefaultEndpoint(t *testing.T) {
	if c := New(Config{DefaultEndpoint: "https://x.example/nic/update"}); c.cfg.Endpoint != "https://x.example/nic/update" {
		t.Errorf("endpoint = %q", c.cfg.Endpoint)
	}
	if c := New(Config{Endpoint: "https://y.example", DefaultEndpoint: "https://x.example"}); c.cfg.Endpoint != "https://y.example" {
		t.Errorf("endpoint = %q", c.cfg.Endpoint)
	}
}
