package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/health"
	"github.com/brnl/docker-ddns-updater/internal/updater"
)

func testHandler(statusPage bool) http.Handler {
	now := time.Now()
	st := health.NewStatus(time.Minute)
	st.Tick(true)
	snap := updater.Snapshot{
		LastCheck: now.Add(-3 * time.Second),
		Families:  []updater.FamilyStatus{{Family: "ipv4", Address: "203.0.113.7", ChangedAt: now.Add(-2 * time.Hour)}},
		Hosts: []updater.HostStatus{
			{Hostname: "home.example.com", IPv4: "203.0.113.7", InSync: true, LastUpdate: now.Add(-2 * time.Hour)},
			{Hostname: "vpn.example.com", Failures: 2, LastError: "<script>alert(1)</script>", NextAttempt: now.Add(time.Minute)},
		},
	}
	return Handler(Options{
		Info:       Info{Version: "1.2.3", Provider: "mijnhost", IPv4Enabled: true, IPv4Sources: []string{"https://api.ipify.org"}, Interval: 10 * time.Second, Started: now.Add(-time.Hour)},
		StatusPage: statusPage,
		Health:     st,
		Snapshot:   func() updater.Snapshot { return snap },
		Now:        func() time.Time { return now },
	})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestStatusPage(t *testing.T) {
	rec := get(t, testHandler(true), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{"home.example.com", "203.0.113.7", "In sync", "Update failed", "changed 2h ago", "retry in 1m", "1.2.3"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if strings.Contains(body, "<script>") {
		t.Error("error text was not escaped")
	}

	// The inline stylesheet must match the hash allowed by the CSP.
	start := strings.Index(body, "<style>") + len("<style>")
	end := strings.Index(body, "</style>")
	sum := sha256.Sum256([]byte(body[start:end]))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Errorf("CSP %q does not allow the rendered stylesheet", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing security headers")
	}
}

func TestStatusJSON(t *testing.T) {
	rec := get(t, testHandler(true), "/status.json")
	var body struct {
		Ready bool `json:"ready"`
		Info  struct {
			Version  string `json:"version"`
			Interval string `json:"interval"`
		} `json:"info"`
		Hosts []updater.HostStatus `json:"hosts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Ready || body.Info.Version != "1.2.3" || body.Info.Interval != "10s" || len(body.Hosts) != 2 {
		t.Errorf("unexpected body: %s", rec.Body)
	}
}

func TestStatusPageDisabled(t *testing.T) {
	h := testHandler(false)
	if rec := get(t, h, "/"); rec.Code != http.StatusNotFound {
		t.Errorf("/ status = %d", rec.Code)
	}
	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz status = %d", rec.Code)
	}
}

func TestUnknownPath(t *testing.T) {
	if rec := get(t, testHandler(true), "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0: "0s", 10 * time.Second: "10s", 5 * time.Minute: "5m", time.Hour: "1h",
		90 * time.Minute: "1h 30m", 49 * time.Hour: "2d 1h", -time.Second: "0s",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
