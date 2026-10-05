package mijnhost

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

func TestUpdateRequest(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = w.Write([]byte("good 203.0.113.7"))
	}))
	defer srv.Close()

	p := New(srv.URL+"/nic/update", "user", "p@ss:word", "ua/1", time.Second)
	err := p.Update(context.Background(), provider.Request{
		Hostname: "home.example.com",
		IPv4:     netip.MustParseAddr("203.0.113.7"),
		IPv6:     netip.MustParseAddr("2001:db8::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL.Path != "/nic/update" {
		t.Errorf("path = %s", got.URL.Path)
	}
	q := got.URL.Query()
	if q.Get("hostname") != "home.example.com" || q.Get("myip") != "203.0.113.7" || q.Get("myipv6") != "2001:db8::1" {
		t.Errorf("query = %s", got.URL.RawQuery)
	}
	if u, pw, ok := got.BasicAuth(); !ok || u != "user" || pw != "p@ss:word" {
		t.Errorf("basic auth = %q %q %v", u, pw, ok)
	}
	if got.UserAgent() != "ua/1" {
		t.Errorf("user agent = %q", got.UserAgent())
	}
}

func TestUpdateOmitsUnsetFamilies(t *testing.T) {
	var query url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		_, _ = w.Write([]byte("nochg"))
	}))
	defer srv.Close()

	p := New(srv.URL, "u", "p", "ua", time.Second)
	if err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv6: netip.MustParseAddr("2001:db8::1")}); err != nil {
		t.Fatal(err)
	}
	if query.Has("myip") || query.Get("myipv6") != "2001:db8::1" {
		t.Errorf("query = %v", query)
	}
	if err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com"}); err == nil {
		t.Error("expected error for request without addresses")
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer srv.Close()

	p := New(srv.URL, "u", "p", "ua", time.Second)
	if err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv4: netip.MustParseAddr("203.0.113.7")}); err == nil {
		t.Error("expected error on redirect")
	}
	if hit {
		t.Error("redirect was followed")
	}
}

func TestInterpret(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		ok        bool
		permanent bool
	}{
		{200, "good 1.2.3.4", true, false},
		{200, "nochg 1.2.3.4\n", true, false},
		{200, "badauth", false, true},
		{200, "nohost", false, true},
		{200, "notfqdn", false, true},
		{200, "abuse", false, true},
		{200, "911", false, false},
		{200, "dnserr", false, false},
		{401, "", false, true},
		{500, "internal error", false, false},
		{200, "<html>surprise</html>", false, false},
	}
	for _, c := range cases {
		err := interpret(c.status, c.body)
		if (err == nil) != c.ok {
			t.Errorf("interpret(%d, %q) = %v, want ok=%v", c.status, c.body, err, c.ok)
		}
		if err != nil && provider.IsPermanent(err) != c.permanent {
			t.Errorf("interpret(%d, %q) permanent = %v, want %v", c.status, c.body, provider.IsPermanent(err), c.permanent)
		}
		if err != nil && strings.Contains(err.Error(), "p@ss") {
			t.Error("error leaks credentials")
		}
	}
}
