// Package limittest is the contract every core.Limiter must pass. A new
// limiter (SQLite, Redis, a Durable Object behind an adapter) calls Run from
// its own tests.
package limittest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// Run checks a limiter. newLimiter must return an empty limiter that reads
// the time from now.
func Run(t *testing.T, newLimiter func(now func() time.Time) core.Limiter) {
	t.Run("every scope must have room", func(t *testing.T) {
		ctx := context.Background()
		now := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)
		l := newLimiter(func() time.Time { return now })
		project := core.Scope{Key: "project:p", Label: "project P", Limits: core.Limits{DailyRequests: 3}}
		tokA := core.Scope{Key: "token:a", Label: "token a"}
		tokB := core.Scope{Key: "token:b", Label: "token b", Limits: core.Limits{DailyRequests: 1}}

		if err := l.Allow(ctx, []core.Scope{project, tokB}); err != nil {
			t.Fatal(err)
		}
		// b is full: refused, and the project count must not move.
		var le *core.LimitError
		if err := l.Allow(ctx, []core.Scope{project, tokB}); !errors.As(err, &le) || le.Scope != "token b" || le.Kind != "daily" {
			t.Fatalf("got %v", err)
		}
		if n, _ := l.UsedToday(ctx, "project:p"); n != 1 {
			t.Fatalf("refused request was counted: project used %d", n)
		}
		// a has no limit of its own, but the project's limit (3) still applies.
		_ = l.Allow(ctx, []core.Scope{project, tokA})
		_ = l.Allow(ctx, []core.Scope{project, tokA})
		if err := l.Allow(ctx, []core.Scope{project, tokA}); !errors.As(err, &le) || le.Scope != "project P" {
			t.Fatalf("project limit not applied: %v", err)
		}
		if n, _ := l.UsedToday(ctx, "token:a"); n != 2 {
			t.Fatalf("token a used %d, want 2", n)
		}
		now = now.Add(2 * time.Hour) // next day (UTC)
		if err := l.Allow(ctx, []core.Scope{project, tokB}); err != nil {
			t.Fatalf("limits should reset the next day: %v", err)
		}
		if n, _ := l.UsedToday(ctx, "token:a"); n != 0 {
			t.Fatalf("yesterday's count shown today: %d", n)
		}
	})

	t.Run("per minute", func(t *testing.T) {
		ctx := context.Background()
		now := time.Date(2026, 10, 31, 10, 0, 10, 0, time.UTC)
		l := newLimiter(func() time.Time { return now })
		s := []core.Scope{{Key: "token:x", Label: "token x", Limits: core.Limits{PerMinute: 2}}}
		_ = l.Allow(ctx, s)
		_ = l.Allow(ctx, s)
		var le *core.LimitError
		if err := l.Allow(ctx, s); !errors.As(err, &le) || le.Kind != "per-minute" {
			t.Fatalf("third in a minute: %v", err)
		}
		now = now.Add(time.Minute)
		if err := l.Allow(ctx, s); err != nil {
			t.Fatalf("new minute: %v", err)
		}
		if n, _ := l.UsedToday(ctx, "token:x"); n != 3 {
			t.Fatalf("daily count %d, want 3", n)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		l := newLimiter(time.Now)
		if n, err := l.UsedToday(context.Background(), "token:never"); err != nil || n != 0 {
			t.Fatalf("got %d, %v", n, err)
		}
	})
}
