package ipdetect

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		family Family
		in     string
		ok     bool
	}{
		{IPv4, "203.0.113.7\n", true},
		{IPv4, "  8.8.8.8 ", true},
		{IPv4, "::ffff:8.8.8.8", true},
		{IPv4, "192.168.1.1", false},
		{IPv4, "10.0.0.1", false},
		{IPv4, "100.64.0.1", false},
		{IPv4, "127.0.0.1", false},
		{IPv4, "2001:4860:4860::8888", false},
		{IPv4, "<html>", false},
		{IPv6, "2001:4860:4860::8888", true},
		{IPv6, "fd00::1", false},
		{IPv6, "fe80::1", false},
		{IPv6, "::1", false},
		{IPv6, "8.8.8.8", false},
		{IPv6, "::ffff:8.8.8.8", false},
	}
	for _, c := range cases {
		_, err := Parse(c.family, c.in)
		if (err == nil) != c.ok {
			t.Errorf("Parse(%v, %q) err = %v, want ok=%v", c.family, c.in, err, c.ok)
		}
	}
}

func server(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestDetect(t *testing.T) {
	good := server(t, 200, "203.0.113.7")
	same := server(t, 200, "203.0.113.7\n")
	other := server(t, 200, "198.51.100.1")
	broken := server(t, 500, "oops")
	private := server(t, 200, "192.168.1.10")

	cases := []struct {
		name    string
		sources []string
		want    string
	}{
		{"agree", []string{good, same}, "203.0.113.7"},
		{"one fails", []string{broken, good}, "203.0.113.7"},
		{"invalid ignored", []string{private, good}, "203.0.113.7"},
		{"disagree", []string{good, other}, ""},
		{"all fail", []string{broken, private}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := New(IPv4, c.sources, 2*time.Second, "test", nil)
			addr, err := d.Detect(context.Background())
			if c.want == "" {
				if err == nil {
					t.Fatalf("expected error, got %s", addr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr.String() != c.want {
				t.Errorf("got %s, want %s", addr, c.want)
			}
		})
	}
}

func TestLogsSourceFailureAndRecovery(t *testing.T) {
	healthy := true
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("203.0.113.7"))
	}))
	defer flaky.Close()
	good := server(t, 200, "203.0.113.7")

	var logs bytes.Buffer
	d := New(IPv4, []string{good, flaky.URL}, 2*time.Second, "test", slog.New(slog.NewTextHandler(&logs, nil)))
	ctx := context.Background()

	healthy = false
	if addr, err := d.Detect(ctx); err != nil || addr.String() != "203.0.113.7" {
		t.Fatalf("Detect = %s, %v", addr, err)
	}
	if !strings.Contains(logs.String(), "IP source failed") || !strings.Contains(logs.String(), flaky.URL) {
		t.Fatalf("failing source not logged while consensus held: %s", logs.String())
	}
	logs.Reset()
	if _, err := d.Detect(ctx); err != nil || logs.Len() != 0 {
		t.Fatalf("repeated failure logged again: %v %s", err, logs.String())
	}
	healthy = true
	if _, err := d.Detect(ctx); err != nil || !strings.Contains(logs.String(), "IP source recovered") {
		t.Fatalf("recovery not logged: %v %s", err, logs.String())
	}
}
