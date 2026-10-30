// Command ddns-updater monitors the public IP address and updates DDNS
// records when it changes.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brnl/docker-ddns-updater/internal/config"
	"github.com/brnl/docker-ddns-updater/internal/health"
	"github.com/brnl/docker-ddns-updater/internal/ipdetect"
	"github.com/brnl/docker-ddns-updater/internal/provider"
	"github.com/brnl/docker-ddns-updater/internal/provider/mijnhost"
	"github.com/brnl/docker-ddns-updater/internal/updater"
	"github.com/brnl/docker-ddns-updater/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: %s [healthcheck|version]\n", os.Args[0])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := newLogger(cfg)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	userAgent := fmt.Sprintf("docker-ddns-updater/%s (+https://github.com/brnl/docker-ddns-updater)", version)

	var prov provider.Provider
	switch cfg.Provider {
	case "mijnhost":
		prov = mijnhost.New(os.Getenv("DDNS_MIJNHOST_ENDPOINT"), cfg.Username, cfg.Password, userAgent, cfg.Timeout)
	}

	var detectors []updater.Detector
	if cfg.IPv4Enabled {
		detectors = append(detectors, ipdetect.New(ipdetect.IPv4, cfg.IPv4Sources, cfg.Timeout, userAgent, log))
	}
	if cfg.IPv6Enabled {
		detectors = append(detectors, ipdetect.New(ipdetect.IPv6, cfg.IPv6Sources, cfg.Timeout, userAgent, log))
	}

	// A cycle can include IP detection plus a DNS lookup and an update per
	// hostname; allow a few missed intervals before reporting unhealthy.
	staleness := 3*cfg.Interval + time.Duration(2+3*len(cfg.Hostnames))*cfg.Timeout
	status := health.NewStatus(staleness)

	// The effective configuration, without credentials.
	startAttrs := []any{
		"version", version,
		"provider", prov.Name(),
		"hostnames", strings.Join(cfg.Hostnames, ","),
		"ipv4", cfg.IPv4Enabled,
		"ipv6", cfg.IPv6Enabled,
		"interval", cfg.Interval.String(),
		"timeout", cfg.Timeout.String(),
		"dns_recheck_interval", cfg.DNSRecheckInterval.String(),
		"dns_server", cmp.Or(cfg.DNSServer, "system resolver"),
		"heartbeat_interval", cfg.Heartbeat.String(),
		"log_level", cfg.LogLevel,
		"dry_run", cfg.DryRun,
	}
	if cfg.IPv4Enabled {
		startAttrs = append(startAttrs, "ipv4_sources", strings.Join(cfg.IPv4Sources, ","))
	}
	if cfg.IPv6Enabled {
		startAttrs = append(startAttrs, "ipv6_sources", strings.Join(cfg.IPv6Sources, ","))
	}
	log.Info("starting ddns-updater", startAttrs...)
	if cfg.DryRun {
		log.Warn("dry run enabled: DNS records will not be changed")
	}

	u := updater.New(updater.Options{
		Provider:           prov,
		Detectors:          detectors,
		Hostnames:          cfg.Hostnames,
		Interval:           cfg.Interval,
		DNSRecheckInterval: cfg.DNSRecheckInterval,
		Resolver:           newResolver(cfg.DNSServer, cfg.Timeout),
		Health:             status,
		DryRun:             cfg.DryRun,
		Logger:             log,
		Heartbeat:          cfg.Heartbeat,
	})

	if addr := listenAddr(cfg.ListenAddr); addr != "" {
		handler := web.Handler(web.Options{
			Info: web.Info{
				Version:            version,
				Provider:           prov.Name(),
				IPv4Enabled:        cfg.IPv4Enabled,
				IPv6Enabled:        cfg.IPv6Enabled,
				IPv4Sources:        sourcesIf(cfg.IPv4Enabled, cfg.IPv4Sources),
				IPv6Sources:        sourcesIf(cfg.IPv6Enabled, cfg.IPv6Sources),
				Interval:           cfg.Interval,
				DNSRecheckInterval: cfg.DNSRecheckInterval,
				DryRun:             cfg.DryRun,
				Started:            time.Now(),
			},
			StatusPage: cfg.StatusPage,
			Metrics:    cfg.Metrics,
			Health:     status,
			Snapshot:   u.Snapshot,
		})
		go func() {
			if err := web.Serve(ctx, addr, handler); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("HTTP server stopped", "error", err.Error())
				stop()
			}
		}()
		log.Info("serving HTTP", "addr", addr, "status_page", cfg.StatusPage, "metrics", cfg.Metrics)
	}

	u.Run(ctx)
	log.Info("shutting down")
	return nil
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

// newResolver returns the system resolver, or one that sends all queries to
// server (a host:port normalized by config). A hostname in server is resolved
// once per connection with the system resolver.
func newResolver(server string, timeout time.Duration) updater.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: timeout}
	return fixedServerResolver{
		server: server,
		r: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, server)
			},
		},
	}
}

// fixedServerResolver reports the configured server in lookup errors; the Go
// resolver would otherwise name the server from /etc/resolv.conf, which was
// not actually queried.
type fixedServerResolver struct {
	r      *net.Resolver
	server string
}

func (f fixedServerResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	addrs, err := f.r.LookupNetIP(ctx, network, host)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		dnsErr.Server = f.server
	}
	return addrs, err
}

func sourcesIf(enabled bool, s []string) []string {
	if enabled {
		return s
	}
	return nil
}

func listenAddr(addr string) string {
	switch strings.ToLower(addr) {
	case "", "off", "false", "disabled", "none":
		return ""
	}
	return addr
}

func healthcheck() int {
	addr := strings.TrimSpace(os.Getenv("DDNS_LISTEN_ADDR"))
	if addr == "" {
		addr = ":8080"
	}
	if addr = listenAddr(addr); addr == "" {
		return 0 // HTTP server disabled
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid DDNS_LISTEN_ADDR:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if err := health.Probe("http://" + net.JoinHostPort(host, port) + "/healthz"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
