package usage

import (
	"context"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// A long-running process doesn't keep hours forever: the rollup drops those
// older than it keeps as newer entries come in.
func TestRollupKeeping(t *testing.T) {
	r := NewRollupKeeping(48 * time.Hour)
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	r.Add(core.Entry{Time: t0, Service: "openai", Status: 200})
	r.Add(core.Entry{Time: t0.Add(24 * time.Hour), Service: "openai", Status: 200})
	rows, _ := r.Metrics(context.Background(), Query{By: []string{"hour"}})
	if len(rows) != 2 {
		t.Fatalf("rows %d, want 2", len(rows))
	}
	r.Add(core.Entry{Time: t0.Add(50 * time.Hour), Service: "openai", Status: 200})
	rows, _ = r.Metrics(context.Background(), Query{By: []string{"hour"}})
	if len(rows) != 2 || rows[0].Hour.Equal(t0) || rows[1].Hour.Equal(t0) {
		t.Fatalf("the oldest hour is kept: %+v", rows)
	}

	// An entry stamped years ahead (a clock jump) prunes from now, not
	// from then.
	now := time.Now().UTC().Truncate(time.Hour)
	r = NewRollupKeeping(48 * time.Hour)
	r.Add(core.Entry{Time: now, Service: "openai", Status: 200})
	r.Add(core.Entry{Time: now.Add(5 * 365 * 24 * time.Hour), Service: "openai", Status: 200})
	if rows, _ = r.Metrics(context.Background(), Query{By: []string{"hour"}}); len(rows) != 2 {
		t.Fatalf("a future entry pruned the present: %+v", rows)
	}
	// ...and pruning goes on for real entries after it.
	r = NewRollupKeeping(48 * time.Hour)
	r.Add(core.Entry{Time: now.Add(5 * 365 * 24 * time.Hour), Service: "openai", Status: 200})
	r.Add(core.Entry{Time: now.Add(-100 * time.Hour), Service: "openai", Status: 200})
	r.Add(core.Entry{Time: now.Add(time.Hour), Service: "anthropic", Status: 200}) // an hour on: time to prune
	rows, _ = r.Metrics(context.Background(), Query{By: []string{"hour", "service"}})
	for _, row := range rows {
		if row.Hour.Equal(now.Add(-100 * time.Hour)) {
			t.Fatalf("pruning stopped after a future entry: %+v", rows)
		}
	}
}
