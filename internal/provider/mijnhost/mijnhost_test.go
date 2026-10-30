package mijnhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	resp, err := p.Update(context.Background(), provider.Request{
		Hostname: "home.example.com",
		IPv4:     netip.MustParseAddr("203.0.113.7"),
		IPv6:     netip.MustParseAddr("2001:db8::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != "good 203.0.113.7" {
		t.Errorf("response = %q", resp)
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
	if _, err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv6: netip.MustParseAddr("2001:db8::1")}); err != nil {
		t.Fatal(err)
	}
	if query.Has("myip") || query.Get("myipv6") != "2001:db8::1" {
		t.Errorf("query = %v", query)
	}
	if _, err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com"}); err == nil {
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
	if _, err := p.Update(context.Background(), provider.Request{Hostname: "h.example.com", IPv4: netip.MustParseAddr("203.0.113.7")}); err == nil {
		t.Error("expected error on redirect")
	}
	if hit {
		t.Error("redirect was followed")
	}
}
