package sqlite

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

// Events is the request log in the database: a core.Sink and a
// core.LogReader. Entries older than Keep are deleted as new ones arrive.
type Events struct {
	db   *DB
	Keep time.Duration
	Now  func() time.Time

	mu        sync.Mutex // guards lastPrune; Add runs on every proxied request
	lastPrune time.Time
}

// NewEvents returns the request log over d, keeping keep (30 days if 0).
// The first time, it rolls the log up into the hourly metrics table.
func NewEvents(d *DB, keep time.Duration) *Events {
	if keep <= 0 {
		keep = 30 * 24 * time.Hour
	}
	_ = backfill(context.Background(), d)
	return &Events{db: d, Keep: keep, Now: time.Now}
}

// Add records an entry and adds it to its metrics rows, in one
// transaction; a failed metrics write never loses the entry itself.
// Entries never hold headers, query strings or bodies, so no key can end
// up here.
func (e *Events) Add(en core.Entry) {
	b, err := json.Marshal(en)
	if err != nil {
		return
	}
	ctx := context.Background()
	if tx, err := e.db.db.BeginTx(ctx, nil); err == nil {
		if _, err := tx.ExecContext(ctx, "INSERT INTO events (time, data) VALUES (?, ?)", en.Time.UTC().Format(time.RFC3339Nano), string(b)); err != nil {
			_ = tx.Rollback()
		} else {
			if _, err := tx.ExecContext(ctx, "SAVEPOINT metrics"); err == nil {
				if err := addRow(ctx, tx, usage.RowFor(en), true); err != nil {
					log.Printf("keystub: usage metrics not updated: %v", err)
					_, _ = tx.ExecContext(ctx, "ROLLBACK TO metrics")
				}
				_, _ = tx.ExecContext(ctx, "RELEASE metrics")
			}
			_ = tx.Commit()
		}
	}
	// Prune at most once an hour.
	now := e.Now()
	e.mu.Lock()
	prune := now.Sub(e.lastPrune) > time.Hour
	if prune {
		e.lastPrune = now
	}
	e.mu.Unlock()
	if prune {
		_, _ = e.db.db.ExecContext(ctx, "DELETE FROM events WHERE time < ?", now.Add(-e.Keep).UTC().Format(time.RFC3339Nano))
		_, _ = e.db.db.ExecContext(ctx, "DELETE FROM metrics_hourly WHERE hour < ?", now.Add(-keepMetrics).UTC().Format(hourFormat))
	}
}

// Recent returns up to n entries, newest first.
func (e *Events) Recent(n int) []core.Entry {
	rows, err := e.db.ro.QueryContext(context.Background(), "SELECT data FROM events ORDER BY id DESC LIMIT ?", n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []core.Entry
	for rows.Next() {
		var raw string
		var en core.Entry
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &en) == nil {
			out = append(out, en)
		}
	}
	return out
}

var (
	_ core.Sink      = (*Events)(nil)
	_ core.LogReader = (*Events)(nil)
)
