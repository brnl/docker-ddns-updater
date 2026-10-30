// Package noip configures the dyndns2 client for No-IP
// (https://www.noip.com/integrate/request):
//
//	GET https://dynupdate.no-ip.com/nic/update?hostname=<hostname>&myip=<ipv4>,<ipv6>
//
// No-IP requires that a client stops sending updates after an error response
// (nohost, badauth, badagent, !donator, abuse) until the user has fixed the
// problem, and waits at least 30 minutes after a server error (911 or HTTP
// 5xx); clients that don't risk being blocked.
package noip

import (
	"time"

	"github.com/brnl/docker-ddns-updater/internal/provider/dyndns2"
)

// DefaultEndpoint is the No-IP update URL.
const DefaultEndpoint = "https://dynupdate.no-ip.com/nic/update"

// ServerErrorRetryAfter is the minimum wait No-IP requires after 911/5xx.
const ServerErrorRetryAfter = 30 * time.Minute

// New returns a No-IP provider. The username is the account e-mail address
// (or DDNS Key username). An empty endpoint uses DefaultEndpoint.
func New(endpoint, username, password, userAgent string, timeout time.Duration) *dyndns2.Client {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return dyndns2.New(dyndns2.Config{
		Name:        "noip",
		DisplayName: "No-IP",
		Endpoint:    endpoint,
		Username:    username,
		Password:    password,
		UserAgent:   userAgent,
		Timeout:     timeout,
		// No-IP's preferred form for dual-stack: myip=<ipv4>,<ipv6>.
		SetIPs:                dyndns2.CombinedIPs,
		StopOnRejection:       true,
		ServerErrorRetryAfter: ServerErrorRetryAfter,
	})
}
