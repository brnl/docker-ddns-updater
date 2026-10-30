package condlog

import (
	"testing"
	"time"
)

func TestTracker(t *testing.T) {
	var tr Tracker
	now := time.Unix(1_700_000_000, 0)
	step := func(d time.Duration) { now = now.Add(d) }

	if ok, _, _ := tr.Recover(now); ok {
		t.Fatal("recovered without failing")
	}
	if ev := tr.Fail(now, "boom"); ev != Started {
		t.Fatalf("first failure = %v", ev)
	}
	step(time.Minute)
	if ev := tr.Fail(now, "boom"); ev != None {
		t.Fatalf("repeat failure = %v", ev)
	}
	step(time.Minute)
	if ev := tr.Fail(now, "bang"); ev != Changed {
		t.Fatalf("changed failure = %v", ev)
	}
	step(DefaultReminder - time.Second)
	if ev := tr.Fail(now, "bang"); ev != None {
		t.Fatalf("before reminder = %v", ev)
	}
	step(time.Second)
	if ev := tr.Fail(now, "bang"); ev != Reminder {
		t.Fatalf("reminder = %v", ev)
	}
	if !tr.Failing() || tr.Count() != 5 {
		t.Fatalf("failing=%v count=%d", tr.Failing(), tr.Count())
	}
	step(time.Minute)
	ok, d, n := tr.Recover(now)
	if !ok || n != 5 || d != 3*time.Minute+DefaultReminder {
		t.Fatalf("recover = %v %s %d", ok, d, n)
	}
	if tr.Failing() || tr.Fail(now, "boom") != Started {
		t.Fatal("tracker not reset after recovery")
	}
}

func TestReminderDisabled(t *testing.T) {
	tr := Tracker{Reminder: -1}
	now := time.Unix(0, 0)
	tr.Fail(now, "x")
	if ev := tr.Fail(now.Add(24*time.Hour), "x"); ev != None {
		t.Fatalf("reminder fired while disabled: %v", ev)
	}
}
