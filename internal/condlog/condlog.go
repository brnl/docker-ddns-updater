// Package condlog decides when a recurring failure condition is worth a log
// line: when it starts, when its message changes, periodically while it
// persists, and once when it clears. This keeps logs quiet in steady state
// without hiding an ongoing problem.
package condlog

import "time"

// DefaultReminder is how often an unchanged, ongoing failure is logged again.
const DefaultReminder = 15 * time.Minute

// Event says whether (and why) a failure should be logged.
type Event int

const (
	// None: the failure is ongoing and was logged recently; stay quiet.
	None Event = iota
	// Started: the condition just started failing.
	Started
	// Changed: still failing, but with a different message.
	Changed
	// Reminder: still failing with the same message; periodic reminder.
	Reminder
)

func (e Event) String() string {
	switch e {
	case Started:
		return "started"
	case Changed:
		return "changed"
	case Reminder:
		return "ongoing"
	}
	return ""
}

// Tracker tracks one failure condition. The zero value is ready to use and
// reminds every DefaultReminder. It is not safe for concurrent use.
type Tracker struct {
	// Reminder overrides DefaultReminder; negative disables reminders.
	Reminder time.Duration

	failing bool
	msg     string
	since   time.Time
	lastLog time.Time
	count   int
}

// Fail records a failure at now and reports whether to log it.
func (t *Tracker) Fail(now time.Time, msg string) Event {
	t.count++
	ev := None
	switch {
	case !t.failing:
		t.failing, t.since = true, now
		ev = Started
	case msg != t.msg:
		ev = Changed
	case t.reminder() > 0 && now.Sub(t.lastLog) >= t.reminder():
		ev = Reminder
	}
	t.msg = msg
	if ev != None {
		t.lastLog = now
	}
	return ev
}

// Recover records a success at now. If the condition was failing it reports
// true with how long it lasted and how many failures were recorded.
func (t *Tracker) Recover(now time.Time) (recovered bool, duration time.Duration, failures int) {
	if !t.failing {
		return false, 0, 0
	}
	recovered, duration, failures = true, now.Sub(t.since), t.count
	*t = Tracker{Reminder: t.Reminder}
	return
}

// Failing reports whether the condition is currently failing.
func (t *Tracker) Failing() bool { return t.failing }

// Since returns when the current failure started (zero if not failing).
func (t *Tracker) Since() time.Time { return t.since }

// Count returns the number of failures since the condition started.
func (t *Tracker) Count() int { return t.count }

func (t *Tracker) reminder() time.Duration {
	if t.Reminder == 0 {
		return DefaultReminder
	}
	return t.Reminder
}
