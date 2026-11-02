// Package limit holds Limiter adapters. Memory counts in this process and
// resets on restart; a shared one (Redis, Postgres) comes with several proxies.
package limit

import (
	"context"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

type window struct {
	day      string
	dayCount int
	minute   string
	minCount int
}

// Memory implements core.Limiter with fixed daily and per-minute windows.
type Memory struct {
	mu  sync.Mutex
	m   map[string]window
	Now func() time.Time
}

// NewMemory returns an empty in-memory limiter.
func NewMemory() *Memory { return &Memory{m: map[string]window{}, Now: time.Now} }

func (l *Memory) current(key string, day, minute string) window {
	w := l.m[key]
	if w.day != day {
		w.day, w.dayCount = day, 0
	}
	if w.minute != minute {
		w.minute, w.minCount = minute, 0
	}
	return w
}

// Allow checks every scope first and counts the request against all of
// them only if each has room, so a refused request uses up nothing.
func (l *Memory) Allow(_ context.Context, scopes []core.Scope) error {
	now := l.Now().UTC()
	day, minute := now.Format("2006-01-02"), now.Format("2006-01-02T15:04")
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range scopes {
		w := l.current(s.Key, day, minute)
		if s.Limits.DailyRequests > 0 && w.dayCount >= s.Limits.DailyRequests {
			return &core.LimitError{Scope: s.Label, Kind: "daily"}
		}
		if s.Limits.PerMinute > 0 && w.minCount >= s.Limits.PerMinute {
			return &core.LimitError{Scope: s.Label, Kind: "per-minute"}
		}
	}
	for _, s := range scopes {
		w := l.current(s.Key, day, minute)
		w.dayCount++
		w.minCount++
		l.m[s.Key] = w
	}
	return nil
}

func (l *Memory) UsedToday(_ context.Context, key string) (int, error) {
	day := l.Now().UTC().Format("2006-01-02")
	l.mu.Lock()
	defer l.mu.Unlock()
	if w := l.m[key]; w.day == day {
		return w.dayCount, nil
	}
	return 0, nil
}
