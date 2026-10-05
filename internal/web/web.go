// Package web serves the status page and health endpoints.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/health"
	"github.com/brnl/docker-ddns-updater/internal/updater"
)

var (
	//go:embed status.html
	pageHTML string
	//go:embed status.css
	pageCSS string

	page = template.Must(template.New("status").Funcs(template.FuncMap{
		"join":     strings.Join,
		"stamp":    func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
		"duration": humanDuration,
		// Replaced per request so relative times share a single "now".
		"ago":   func(time.Time) string { return "" },
		"until": func(time.Time) string { return "" },
	}).Parse(pageHTML))

	// The page has no scripts and only this inline stylesheet, so the CSP
	// allows exactly that and nothing else.
	contentSecurityPolicy = func() string {
		sum := sha256.Sum256([]byte(pageCSS))
		return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
			"'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	}()
)

// Info is the static configuration shown on the status page. It must never
// contain credentials.
type Info struct {
	Version            string        `json:"version"`
	Provider           string        `json:"provider"`
	IPv4Enabled        bool          `json:"ipv4_enabled"`
	IPv6Enabled        bool          `json:"ipv6_enabled"`
	IPv4Sources        []string      `json:"ipv4_sources,omitempty"`
	IPv6Sources        []string      `json:"ipv6_sources,omitempty"`
	Interval           time.Duration `json:"-"`
	DNSRecheckInterval time.Duration `json:"-"`
	DryRun             bool          `json:"dry_run"`
	Started            time.Time     `json:"started"`
}

// Options configures the handler.
type Options struct {
	Info Info
	// StatusPage enables "/" and "/status.json"; health endpoints are always
	// served.
	StatusPage bool
	Health     *health.Status
	Snapshot   func() updater.Snapshot
	Now        func() time.Time
}

// Handler returns the HTTP handler for the status page and health endpoints.
func Handler(opts Options) http.Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	mux := http.NewServeMux()
	h := opts.Health.Handler()
	mux.Handle("GET /healthz", h)
	mux.Handle("GET /readyz", h)
	if opts.StatusPage {
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { servePage(w, opts) })
		mux.HandleFunc("GET /status.json", func(w http.ResponseWriter, _ *http.Request) { serveJSON(w, opts) })
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Content-Security-Policy", contentSecurityPolicy)
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "no-referrer")
		hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
		hdr.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type badge struct{ Label, Class string }

type hostView struct {
	updater.HostStatus
	State badge
}

type pageData struct {
	Info     Info
	Snapshot updater.Snapshot
	Hosts    []hostView
	Overall  badge
	Uptime   time.Duration
	Refresh  int
	CSS      template.CSS
}

func servePage(w http.ResponseWriter, opts Options) {
	now := opts.Now()
	snap := opts.Snapshot()
	data := pageData{
		Info:     opts.Info,
		Snapshot: snap,
		Uptime:   now.Sub(opts.Info.Started),
		Refresh:  max(int(opts.Info.Interval.Seconds()), 5),
		CSS:      template.CSS(pageCSS),
	}
	switch {
	case snap.LastCheck.IsZero():
		data.Overall = badge{"Starting", "idle"}
	case opts.Health.Ready() == nil:
		data.Overall = badge{"All systems normal", "ok"}
	default:
		data.Overall = badge{"Degraded", "err"}
	}
	for _, h := range snap.Hosts {
		v := hostView{HostStatus: h}
		switch {
		case h.Failures > 0:
			v.State = badge{"Update failed", "err"}
		case h.InSync:
			v.State = badge{"In sync", "ok"}
		case snap.LastCheck.IsZero():
			v.State = badge{"Pending", "idle"}
		default:
			v.State = badge{"Out of sync", "warn"}
		}
		data.Hosts = append(data.Hosts, v)
	}

	// Relative times are rendered against a single "now".
	tmpl, err := page.Clone()
	if err == nil {
		tmpl.Funcs(template.FuncMap{
			"ago": func(t time.Time) string { return humanDuration(now.Sub(t)) + " ago" },
			"until": func(t time.Time) string {
				if d := t.Sub(now); d > 0 {
					return "in " + humanDuration(d)
				}
				return "now"
			},
		})
	}
	var buf bytes.Buffer
	if err == nil {
		err = tmpl.Execute(&buf, data)
	}
	if err != nil {
		http.Error(w, "failed to render status page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func serveJSON(w http.ResponseWriter, opts Options) {
	type info struct {
		Info
		Interval           string `json:"interval"`
		DNSRecheckInterval string `json:"dns_recheck_interval"`
	}
	ready := opts.Health.Ready()
	body := struct {
		Ready  bool   `json:"ready"`
		Reason string `json:"reason,omitempty"`
		Info   info   `json:"info"`
		updater.Snapshot
	}{
		Ready:    ready == nil,
		Info:     info{opts.Info, opts.Info.Interval.String(), opts.Info.DNSRecheckInterval.String()},
		Snapshot: opts.Snapshot(),
	}
	if ready != nil {
		body.Reason = ready.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

// humanDuration formats d coarsely: "12s", "5m", "3h 4m", "2d".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return joinUnits(int(d.Hours()), "h", int(d.Minutes())%60, "m")
	default:
		return joinUnits(int(d.Hours())/24, "d", int(d.Hours())%24, "h")
	}
}

func joinUnits(a int, au string, b int, bu string) string {
	if b == 0 {
		return fmt.Sprintf("%d%s", a, au)
	}
	return fmt.Sprintf("%d%s %d%s", a, au, b, bu)
}

// Serve runs the HTTP server until ctx is cancelled.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
