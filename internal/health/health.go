// Package health exposes liveness/readiness endpoints for the update loop.
package health

import (
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Status tracks the outcome of the update loop.
type Status struct {
	mu        sync.RWMutex
	started   time.Time
	lastTick  time.Time
	lastOK    bool
	everOK    bool
	staleness time.Duration
	now       func() time.Time
}

// NewStatus returns a Status that reports unhealthy when no check cycle has
// completed within staleness.
func NewStatus(staleness time.Duration) *Status {
	return &Status{started: time.Now(), staleness: staleness, now: time.Now}
}

// Tick records a completed check cycle.
func (s *Status) Tick(ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTick = s.now()
	s.lastOK = ok
	s.everOK = s.everOK || ok
}

// Live reports whether the loop is still making progress.
func (s *Status) Live() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	last := s.lastTick
	if last.IsZero() {
		last = s.started
	}
	if age := s.now().Sub(last); age > s.staleness {
		return fmt.Errorf("no check cycle completed for %s", age.Round(time.Second))
	}
	return nil
}

// Ready reports whether the last check cycle succeeded.
func (s *Status) Ready() error {
	if err := s.Live(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.lastOK {
		return errors.New("last check cycle failed")
	}
	return nil
}

// Handler serves /healthz (liveness) and /readyz (readiness).
func (s *Status) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { respond(w, s.Live()) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { respond(w, s.Ready()) })
	return mux
}

func respond(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, err)
		return
	}
	fmt.Fprintln(w, "ok")
}

// Probe performs an HTTP GET against a local health endpoint; used as the
// container HEALTHCHECK since the image has no shell or curl.
func Probe(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %s", resp.Status)
	}
	return nil
}
