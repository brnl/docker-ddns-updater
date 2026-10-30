package noip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/provider"
)

func TestUpdateRequest(t *testing.T) {
	var got *http.Request
	reply := "good 203.0.113.7,2001:db8::1"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()

	p := New(srv.URL+"/nic/update", "me@example.com", "s3cret", "ua/1", time.Second)
	if p.Name() != "noip" {
		t.Errorf("name = %q", p.Name())
	}
	resp, err := p.Update(context.Background(), provider.Request{
		Hostname: "home.ddns.net",
		IPv4:     netip.MustParseAddr("203.0.113.7"),
		IPv6:     netip.MustParseAddr("2001:db8::1"),
	})
	if err != nil || resp != reply {
		t.Fatalf("Update = %q, %v", resp, err)
	}
	q := got.URL.Query()
	if got.URL.Path != "/nic/update" || q.Get("hostname") != "home.ddns.net" || q.Get("myip") != "203.0.113.7,2001:db8::1" || q.Has("myipv6") {
		t.Errorf("request = %s", got.URL)
	}
	if u, pw, ok := got.BasicAuth(); !ok || u != "me@example.com" || pw != "s3cret" {
		t.Errorf("basic auth = %q %q %v", u, pw, ok)
	}
}

func TestErrors(t *testing.T) {
	status, body := http.StatusOK, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	p := New(srv.URL, "u", "p", "ua", time.Second)
	update := func() error {
		_, err := p.Update(context.Background(), provider.Request{Hostname: "h.ddns.net", IPv4: netip.MustParseAddr("203.0.113.7")})
		return err
	}

	// Errors that need user intervention stop all further updates.
	for _, code := range []string{"nohost", "badauth", "badagent", "!donator", "abuse"} {
		body = code
		if err := update(); !provider.StopsUpdates(err) {
			t.Errorf("%s: StopsUpdates = false (%v)", code, err)
		}
	}
	// Server errors: retry no sooner than 30 minutes.
	for _, tc := range []struct {
		status int
		body   string
	}{{200, "911"}, {500, ""}} {
		status, body = tc.status, tc.body
		if after, ok := provider.RetryAfter(update()); !ok || after != 30*time.Minute {
			t.Errorf("%d %q: retry after = %s, %v", tc.status, tc.body, after, ok)
		}
	}
}
