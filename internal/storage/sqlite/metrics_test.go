package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

func TestHourlyMetrics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystub.db")
	d := open(t, path)
	ev := NewEvents(d, 0)
	h := time.Date(2026, 10, 31, 14, 0, 0, 0, time.UTC)
	cost := int64(500)
	for _, e := range []core.Entry{
		{Time: h.Add(time.Minute), Project: "app", Env: "app/dev", TokenID: "tk_1", Service: "openai", Model: "gpt-6-sol", Operation: "chat",
			Status: 200, Outcome: core.OutcomeOK, DurationMs: 400, OverheadMs: 2, Usage: &core.Usage{InputTokens: 100, CachedTokens: 20, OutputTokens: 10}, CostMicros: &cost},
		{Time: h.Add(2 * time.Minute), Project: "app", Env: "app/dev", TokenID: "tk_1", Service: "openai", Model: "gpt-6-sol", Operation: "chat",
			Status: 200, Outcome: core.OutcomeOK, DurationMs: 900, OverheadMs: 4, Usage: &core.Usage{InputTokens: 50, OutputTokens: 5}},
		{Time: h.Add(3 * time.Minute), Project: "app", Env: "app/dev", TokenID: "tk_1", Service: "openai", Status: 401, Outcome: core.OutcomeKeyRejected, DurationMs: 50},
		{Time: h.Add(61 * time.Minute), Project: "app", Env: "app/prod", Service: "openai", Status: 429, Note: "daily limit reached", DurationMs: 0},
	} {
		ev.Add(e)
	}
	ctx := context.Background()
	rows, err := ev.Metrics(ctx, usage.Query{From: h, By: usage.Dimensions})
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows %+v, %v", rows, err)
	}
	all, _ := ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}})
	r := all[0]
	if len(all) != 1 || r.Requests != 4 || r.OK != 2 || r.KeyRejected != 1 || r.Refused != 1 || r.InputTokens != 150 || r.CachedTokens != 20 ||
		r.OutputTokens != 15 || r.CostMicros != 500 || r.Unpriced != 1 || r.OverheadMsSum != 6 || r.DurationMsSum != 1350 {
		t.Fatalf("total %+v", r)
	}
	// 0, 50, 400 and 900 ms: the median is the second, the p95 the last.
	if p50, p95 := r.Percentile(0.5), r.Percentile(0.95); p50 < 25 || p50 > 50 || p95 < 750 || p95 > 1000 {
		t.Fatalf("p50 %d, p95 %d", p50, p95)
	}
	only, _ := ev.Metrics(ctx, usage.Query{From: h, To: h.Add(time.Hour), Env: "app/dev", By: []string{"hour", "model"}})
	if len(only) != 2 || only[0].Requests+only[1].Requests != 3 {
		t.Fatalf("filtered %+v", only)
	}

	// A database from before hourly metrics: events but no rows. Opening it again
	// rolls the log up once.
	if _, err := d.db.Exec("DELETE FROM metrics_hourly"); err != nil {
		t.Fatal(err)
	}
	ev = NewEvents(d, 0)
	again, _ := ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}})
	if len(again) != 1 || again[0].Requests != 4 || again[0].InputTokens != 150 {
		t.Fatalf("backfill %+v", again)
	}
	NewEvents(d, 0) // not twice
	again, _ = ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}})
	if again[0].Requests != 4 {
		t.Fatalf("backfilled twice: %+v", again)
	}
}

func TestAFailedMetricsWriteKeepsTheEntry(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "keystub.db"))
	ev := NewEvents(d, 0)
	// A table from some other version, with columns the upsert doesn't know.
	if _, err := d.db.Exec("DROP TABLE metrics_hourly; CREATE TABLE metrics_hourly (hour TEXT PRIMARY KEY, n INTEGER)"); err != nil {
		t.Fatal(err)
	}
	ev.Add(core.Entry{Time: time.Now(), Service: "openai", Status: 200})
	if got := ev.Recent(5); len(got) != 1 {
		t.Fatalf("entry lost with the metrics row: %+v", got)
	}
}

// Opening a database from another build migrates the metrics tables and
// never loses counts: a missing count column is added, a newer build's
// extra column is kept, and a missing key column copies the rows over.
func TestMetricsTablesMigrateWithoutLosingCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystub.db")
	d := open(t, path)
	ev := NewEvents(d, 0)
	h := time.Date(2026, 10, 31, 14, 0, 0, 0, time.UTC)
	ev.Add(core.Entry{Time: h, Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	for _, q := range []string{
		"ALTER TABLE metrics_hourly DROP COLUMN canceled",
		"ALTER TABLE metrics_total DROP COLUMN canceled",
		"ALTER TABLE metrics_hourly ADD COLUMN from_the_future INTEGER NOT NULL DEFAULT 0",
	} {
		if _, err := d.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	d.Close()
	d = open(t, path)
	ev = NewEvents(d, 0)
	ev.Add(core.Entry{Time: h, Service: "openai", Status: 499, Outcome: core.OutcomeCanceled})
	ctx := context.Background()
	rows, err := ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}})
	if err != nil || len(rows) != 1 || rows[0].Requests != 2 || rows[0].OK != 1 || rows[0].Canceled != 1 {
		t.Fatalf("hourly %+v, %v", rows, err)
	}
	if cols, _ := columns(d.db, "metrics_hourly"); !slices.Contains(cols, "from_the_future") {
		t.Fatalf("a newer build's column was dropped: %v", cols)
	}
	if totals, _ := ev.Totals(ctx); len(totals) != 1 || totals[0].Requests != 2 {
		t.Fatalf("totals %+v", totals)
	}

	// Totals from before the operation was a key: copied, summed by the
	// keys they have.
	if _, err := d.db.Exec(`DROP TABLE metrics_total;
		CREATE TABLE metrics_total (project TEXT, env TEXT, token_id TEXT, service TEXT, model TEXT, requests INTEGER, ok INTEGER, PRIMARY KEY (project, env, token_id, service, model));
		INSERT INTO metrics_total VALUES ('', '', '', 'openai', '', 40, 39), ('', '', '', 'anthropic', '', 2, 2)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d = open(t, path)
	ev = NewEvents(d, 0)
	totals, err := ev.Totals(ctx)
	if err != nil || len(totals) != 2 {
		t.Fatalf("totals %+v, %v", totals, err)
	}
	for _, r := range totals {
		if r.Service == "openai" && (r.Requests != 40 || r.OK != 39) || r.Service == "anthropic" && r.Requests != 2 {
			t.Fatalf("totals lost counts: %+v", totals)
		}
	}
}

// After a downgrade a table's primary key can have a newer build's
// column; nullable columns can hold NULLs. Both are copied over, so
// writes work again and no count is lost.
func TestMetricsTablesWithAnotherKeyAreCopied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystub.db")
	d := open(t, path)
	if _, err := d.db.Exec(`DROP TABLE metrics_total;
		CREATE TABLE metrics_total (project TEXT, env TEXT, token_id TEXT, service TEXT, model TEXT, operation TEXT, region TEXT, requests INTEGER, ok INTEGER,
			PRIMARY KEY (project, env, token_id, service, model, operation, region));
		INSERT INTO metrics_total VALUES ('', '', '', 'openai', '', '', 'eu', 3, NULL), ('', '', '', 'openai', '', '', 'us', 4, 4), (NULL, '', '', 'openai', '', '', 'x', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d = open(t, path)
	ev := NewEvents(d, 0)
	ev.Add(core.Entry{Time: time.Now(), Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	totals, err := ev.Totals(context.Background())
	if err != nil || len(totals) != 1 || totals[0].Requests != 9 || totals[0].OK != 6 {
		t.Fatalf("totals %+v, %v", totals, err)
	}
}

// A table with the right key but nullable columns holding NULLs is copied
// into a NOT NULL one, so reads and upserts work.
func TestMetricsTablesWithNullsAreCopied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keystub.db")
	d := open(t, path)
	if _, err := d.db.Exec(`DROP TABLE metrics_total;
		CREATE TABLE metrics_total (project TEXT, env TEXT, token_id TEXT, service TEXT, model TEXT, operation TEXT, requests INTEGER, ok INTEGER,
			PRIMARY KEY (project, env, token_id, service, model, operation));
		INSERT INTO metrics_total VALUES ('', '', '', 'openai', '', '', 3, NULL), (NULL, '', '', 'openai', '', '', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d = open(t, path)
	ev := NewEvents(d, 0)
	ev.Add(core.Entry{Time: time.Now(), Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	totals, err := ev.Totals(context.Background())
	if err != nil || len(totals) != 1 || totals[0].Requests != 5 || totals[0].OK != 2 {
		t.Fatalf("totals %+v, %v", totals, err)
	}
}

// Hourly rows gone but totals kept: the backfill refills the hours and
// doesn't count the log into the totals a second time.
func TestBackfillDoesNotRecountTotals(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "keystub.db"))
	ev := NewEvents(d, 0)
	h := time.Now().UTC().Truncate(time.Hour)
	ev.Add(core.Entry{Time: h, Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	if _, err := d.db.Exec("DELETE FROM metrics_hourly"); err != nil {
		t.Fatal(err)
	}
	ev = NewEvents(d, 0)
	ctx := context.Background()
	if rows, _ := ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}}); len(rows) != 1 || rows[0].Requests != 1 {
		t.Fatalf("hourly %+v", rows)
	}
	if totals, _ := ev.Totals(ctx); len(totals) != 1 || totals[0].Requests != 1 {
		t.Fatalf("totals counted twice: %+v", totals)
	}
}

// The usage page reads on its own connections: a write in progress on the
// request path's one connection doesn't hold it up, nor it the write.
func TestUsageReadsDontWaitForTheWriter(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "keystub.db"))
	ev := NewEvents(d, 0)
	h := time.Now().UTC().Truncate(time.Hour)
	ev.Add(core.Entry{Time: h, Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	ctx := context.Background()
	tx, err := d.db.BeginTx(ctx, nil) // holds the only write connection
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO events (time, data) VALUES ('x', '{}')"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ev.Metrics(ctx, usage.Query{From: h, By: []string{"service"}})
		if err == nil {
			_, err = ev.Totals(ctx)
		}
		if err == nil && len(ev.Recent(5)) != 1 {
			err = fmt.Errorf("recent")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("usage reads waited for the writer")
	}
	// And they can't write.
	if _, err := d.ro.Exec("DELETE FROM events"); err == nil {
		t.Fatal("the read-only connections wrote")
	}
}

func TestTotalsOutliveHourlyRows(t *testing.T) {
	d := open(t, filepath.Join(t.TempDir(), "keystub.db"))
	ev := NewEvents(d, 0)
	now := time.Now().UTC()
	ev.Now = func() time.Time { return now }
	ev.Add(core.Entry{Time: now.Add(-500 * 24 * time.Hour), Service: "openai", Status: 200, Outcome: core.OutcomeOK})
	ev.Add(core.Entry{Time: now, Service: "openai", Status: 200, Outcome: core.OutcomeOK}) // prunes
	ctx := context.Background()
	hourly, _ := ev.Metrics(ctx, usage.Query{By: []string{"service"}})
	if len(hourly) != 1 || hourly[0].Requests != 1 {
		t.Fatalf("old hour kept: %+v", hourly)
	}
	totals, err := ev.Totals(ctx)
	if err != nil || len(totals) != 1 || totals[0].Requests != 2 {
		t.Fatalf("totals %+v, %v", totals, err)
	}

	// A database with hourly rows but no totals sums the hours once.
	if _, err := d.db.Exec("DELETE FROM metrics_total"); err != nil {
		t.Fatal(err)
	}
	ev = NewEvents(d, 0)
	if totals, _ = ev.Totals(ctx); len(totals) != 1 || totals[0].Requests != 1 {
		t.Fatalf("totals backfill %+v", totals)
	}
}
