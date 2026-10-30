// Package mijnhost configures the dyndns2 client for the mijn.host DynDNS API:
//
//	https://<username>:<password>@mijn.host/nic/update?hostname=<hostname>&myip=<ipv4>&myipv6=<ipv6>
package mijnhost

import (
	"time"

	"github.com/brnl/docker-ddns-updater/internal/provider/dyndns2"
)

// DefaultEndpoint is the mijn.host DynDNS update URL.
const DefaultEndpoint = "https://mijn.host/nic/update"

// New returns a mijn.host provider. An empty endpoint uses DefaultEndpoint.
func New(endpoint, username, password, userAgent string, timeout time.Duration) *dyndns2.Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return dyndns2.New(dyndns2.Config{
		Name:        "mijnhost",
		DisplayName: "mijn.host",
		Endpoint:    endpoint,
		Username:    username,
		Password:    password,
		UserAgent:   userAgent,
		Timeout:     timeout,
		SetIPs:      dyndns2.SeparateIPv6,
	})
}
