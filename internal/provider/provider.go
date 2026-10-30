// Package provider defines the interface implemented by DDNS providers.
package provider

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// Request is a single DNS record update. Unset (zero) addresses are omitted.
type Request struct {
	Hostname string
	IPv4     netip.Addr
	IPv6     netip.Addr
}

// Provider updates DNS records at a DDNS service.
type Provider interface {
	Name() string
	// Update applies req. On success it returns the provider's (short,
	// non-sensitive) response, such as "good 203.0.113.7", for logging.
	Update(ctx context.Context, req Request) (string, error)
}

// PermanentError marks a failure that will not resolve by retrying soon,
// such as invalid credentials or an unknown hostname. Callers should back off
// for a long time to avoid being flagged for abuse. If Stop is set, the
// provider requires that no further updates are sent until the user fixes the
// configuration (the updater stops until restart): for this hostname only,
// or for all hostnames when Account is set (bad credentials, blocked client).
type PermanentError struct {
	Err     error
	Stop    bool
	Account bool
}

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// IsPermanent reports whether err is (or wraps) a PermanentError.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// StopsUpdates reports whether err requires stopping updates until the
// configuration is fixed.
func StopsUpdates(err error) bool {
	var p *PermanentError
	return errors.As(err, &p) && p.Stop
}

// StopsAllUpdates reports whether err requires stopping updates for every
// hostname of the account.
func StopsAllUpdates(err error) bool {
	var p *PermanentError
	return errors.As(err, &p) && p.Stop && p.Account
}

// RetryAfterError is a temporary failure after which the provider requires
// waiting at least After before the next attempt.
type RetryAfterError struct {
	Err   error
	After time.Duration
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// RetryAfter returns the minimum wait err asks for, if any.
func RetryAfter(err error) (time.Duration, bool) {
	var r *RetryAfterError
	if errors.As(err, &r) {
		return r.After, true
	}
	return 0, false
}
