package health

import (
	"testing"
	"time"
)

func TestStatus(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewStatus(time.Minute)
	s.started = now
	s.now = func() time.Time { return now }

	if s.Live() != nil {
		t.Error("should be live during startup grace period")
	}
	if s.Ready() == nil {
		t.Error("should not be ready before the first check")
	}
	s.Tick(true)
	if s.Live() != nil || s.Ready() != nil {
		t.Error("should be live and ready after a successful check")
	}
	s.Tick(false)
	if s.Live() != nil || s.Ready() == nil {
		t.Error("should be live but not ready after a failed check")
	}
	now = now.Add(2 * time.Minute)
	if s.Live() == nil {
		t.Error("should not be live when checks stall")
	}
}
