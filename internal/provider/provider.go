// Package provider defines the interface implemented by DDNS providers.
package provider

import (
	"context"
	"errors"
	"net/netip"
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
	Update(ctx context.Context, req Request) error
}

// PermanentError marks a failure that will not resolve by retrying soon,
// such as invalid credentials or an unknown hostname. Callers should back off
// for a long time to avoid being flagged for abuse.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// IsPermanent reports whether err is (or wraps) a PermanentError.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}
