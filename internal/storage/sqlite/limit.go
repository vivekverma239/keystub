package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// Limiter is a core.Limiter whose counts live in the database, so they
// survive a restart. It uses fixed daily and per-minute windows in UTC,
// like the in-memory limiter.
type Limiter struct {
	db  *DB
	Now func() time.Time
}

// NewLimiter returns a limiter over d.
func NewLimiter(d *DB) *Limiter { return &Limiter{db: d, Now: time.Now} }

type window struct {
	day      string
	dayCount int
	minute   string
	minCount int
}

func readWindow(ctx context.Context, tx *sql.Tx, key, day, minute string) (window, error) {
	w := window{day: day, minute: minute}
	var d, m string
	var dc, mc int
	err := tx.QueryRowContext(ctx, "SELECT day, day_count, minute, min_count FROM counters WHERE key = ?", key).Scan(&d, &dc, &m, &mc)
	if errors.Is(err, sql.ErrNoRows) {
		return w, nil
	}
	if err != nil {
		return w, err
	}
	if d == day {
		w.dayCount = dc
	}
	if m == minute {
		w.minCount = mc
	}
	return w, nil
}

// Allow checks every scope and counts the request against all of them only
// if each has room, in one transaction.
func (l *Limiter) Allow(ctx context.Context, scopes []core.Scope) (err error) {
	now := l.Now().UTC()
	day, minute := now.Format("2006-01-02"), now.Format("2006-01-02T15:04")
	tx, err := l.db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	ws := make([]window, len(scopes))
	for i, s := range scopes {
		if ws[i], err = readWindow(ctx, tx, s.Key, day, minute); err != nil {
			return err
		}
		if s.Limits.DailyRequests > 0 && ws[i].dayCount >= s.Limits.DailyRequests {
			return &core.LimitError{Scope: s.Label, Kind: "daily"}
		}
		if s.Limits.PerMinute > 0 && ws[i].minCount >= s.Limits.PerMinute {
			return &core.LimitError{Scope: s.Label, Kind: "per-minute"}
		}
	}
	for i, s := range scopes {
		_, err = tx.ExecContext(ctx, `INSERT INTO counters (key, day, day_count, minute, min_count) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET day = excluded.day, day_count = excluded.day_count, minute = excluded.minute, min_count = excluded.min_count`,
			s.Key, day, ws[i].dayCount+1, minute, ws[i].minCount+1)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UsedToday returns today's count for a scope key.
func (l *Limiter) UsedToday(ctx context.Context, key string) (int, error) {
	day := l.Now().UTC().Format("2006-01-02")
	var d string
	var n int
	err := l.db.db.QueryRowContext(ctx, "SELECT day, day_count FROM counters WHERE key = ?", key).Scan(&d, &n)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && d != day) {
		return 0, nil
	}
	return n, err
}

var _ core.Limiter = (*Limiter)(nil)
