package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

// MetricsTable is the hourly metrics table's schema. Every count adds, so
// each request is folded in with one upsert; the hosted platform's
// table has the same columns, with an account first in its key.
var MetricsTable = table("metrics_hourly", usage.KeyColumns)

// TotalsTable holds all-time counts by every dimension but the hour. It is
// never pruned, so the counters /metrics serves only go up.
var TotalsTable = table("metrics_total", usage.KeyColumns[1:])

func table(name string, key []string) string {
	var b strings.Builder
	b.WriteString("CREATE TABLE IF NOT EXISTS " + name + " (\n")
	for _, c := range key {
		b.WriteString("  " + c + " TEXT NOT NULL DEFAULT '',\n")
	}
	for _, c := range usage.Columns {
		b.WriteString("  " + c + " INTEGER NOT NULL DEFAULT 0,\n")
	}
	b.WriteString("  PRIMARY KEY (" + strings.Join(key, ", ") + ")\n);\n")
	return b.String()
}

func upsert(name string, key []string) string {
	cols := append(append([]string{}, key...), usage.Columns...)
	var sets []string
	for _, c := range usage.Columns {
		sets = append(sets, c+" = "+c+" + excluded."+c)
	}
	return "INSERT INTO " + name + " (" + strings.Join(cols, ", ") + ") VALUES (" +
		strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ") ON CONFLICT(" +
		strings.Join(key, ", ") + ") DO UPDATE SET " + strings.Join(sets, ", ")
}

var (
	metricsUpsert = upsert("metrics_hourly", usage.KeyColumns)
	totalsUpsert  = upsert("metrics_total", usage.KeyColumns[1:])
)

// ensureMetrics creates the metrics tables and brings an older one up to
// date without losing its counts (CREATE TABLE IF NOT EXISTS never changes
// a table). A missing count column is added. A missing key column can't
// be, since it's in the primary key, so the rows are copied into a new
// table, as they are when the primary key is otherwise different (a newer
// build's key, after a downgrade). Other columns a newer build added are
// left alone: they have defaults.
func ensureMetrics(db *sql.DB) error {
	for _, t := range []struct {
		name, ddl string
		key       []string
	}{{"metrics_hourly", MetricsTable, usage.KeyColumns}, {"metrics_total", TotalsTable, usage.KeyColumns[1:]}} {
		have, err := columns(db, t.name)
		if err != nil {
			return err
		}
		if have == nil {
			if _, err := db.Exec(t.ddl); err != nil {
				return err
			}
			continue
		}
		if err := migrate(db, t.name, t.ddl, t.key, have); err != nil {
			return fmt.Errorf("migrate %s: %w", t.name, err)
		}
	}
	return nil
}

func migrate(db *sql.DB, name, ddl string, key, have []string) error {
	var keep []string // key columns the old table has
	for _, c := range key {
		if slices.Contains(have, c) {
			keep = append(keep, c)
		}
	}
	pk, nullable, err := tableInfo(db, name)
	if err != nil {
		return err
	}
	// NULLs (a table not made by Keystub) would never scan or add up.
	rebuild := !slices.Equal(pk, key) || nullable
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if !rebuild {
		for _, c := range usage.Columns {
			if !slices.Contains(have, c) {
				if _, err := tx.Exec("ALTER TABLE " + name + " ADD COLUMN " + c + " INTEGER NOT NULL DEFAULT 0"); err != nil {
					return err
				}
			}
		}
		return tx.Commit()
	}
	// Copy the counts into the new table, summing rows that now share a key.
	old := name + "_old"
	if _, err := tx.Exec("ALTER TABLE " + name + " RENAME TO " + old); err != nil {
		return err
	}
	if _, err := tx.Exec(ddl); err != nil {
		return err
	}
	var cols, sums, keys []string
	for _, c := range usage.Columns {
		if slices.Contains(have, c) {
			cols = append(cols, c)
			sums = append(sums, "COALESCE(SUM("+c+"), 0)")
		}
	}
	for _, c := range keep {
		keys = append(keys, "COALESCE("+c+", '')")
	}
	if len(keep) > 0 && len(cols) > 0 {
		k := strings.Join(keys, ", ")
		if _, err := tx.Exec("INSERT INTO " + name + " (" + strings.Join(keep, ", ") + ", " + strings.Join(cols, ", ") + ") SELECT " + k + ", " +
			strings.Join(sums, ", ") + " FROM " + old + " GROUP BY " + k); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("DROP TABLE " + old); err != nil {
		return err
	}
	return tx.Commit()
}

// columns lists a table's columns in order, nil if it doesn't exist.
func columns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?) ORDER BY cid", table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// tableInfo lists a table's primary key columns in key order, and
// whether any of the columns Keystub uses may hold NULL.
func tableInfo(db *sql.DB, table string) (pk []string, nullable bool, err error) {
	rows, err := db.Query("SELECT name, pk, \"notnull\" FROM pragma_table_info(?) ORDER BY pk", table)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var k, notNull int
		if err := rows.Scan(&n, &k, &notNull); err != nil {
			return nil, false, err
		}
		if k > 0 {
			pk = append(pk, n)
		}
		if notNull == 0 && (slices.Contains(usage.KeyColumns, n) || slices.Contains(usage.Columns, n)) {
			nullable = true
		}
	}
	return pk, nullable, rows.Err()
}

const hourFormat = "2006-01-02T15:04:05Z"

// keepMetrics is how long hourly rows are kept: they're small, and a year
// on year comparison needs a year.
const keepMetrics = 400 * 24 * time.Hour

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// addRow folds a row into its hour and, if totals, into the all-time
// totals.
func addRow(ctx context.Context, x execer, r usage.Row, totals bool) error {
	args := []any{r.Hour.UTC().Format(hourFormat), r.Project, r.Env, r.TokenID, r.Service, r.Model, r.Operation, r.SavedKey}
	for _, p := range r.Counters() {
		args = append(args, *p)
	}
	if _, err := x.ExecContext(ctx, metricsUpsert, args...); err != nil {
		return err
	}
	if !totals {
		return nil
	}
	_, err := x.ExecContext(ctx, totalsUpsert, args[1:]...)
	return err
}

// backfill rolls up the request log into empty metrics tables, once, so
// the usage page has history from before the tables existed.
func backfill(ctx context.Context, d *DB) error {
	var hourly, totals int
	if err := d.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM metrics_hourly), EXISTS (SELECT 1 FROM metrics_total)").Scan(&hourly, &totals); err != nil {
		return err
	}
	if hourly == 1 {
		if totals == 0 {
			// Only totals are new: sum the hours kept.
			key := strings.Join(usage.KeyColumns[1:], ", ")
			var sums []string
			for _, c := range usage.Columns {
				sums = append(sums, "SUM("+c+")")
			}
			_, err := d.db.ExecContext(ctx, "INSERT INTO metrics_total ("+key+", "+strings.Join(usage.Columns, ", ")+") SELECT "+key+", "+
				strings.Join(sums, ", ")+" FROM metrics_hourly GROUP BY "+key)
			return err
		}
		return nil
	}
	rows, err := d.db.QueryContext(ctx, "SELECT data FROM events ORDER BY id")
	if err != nil {
		return err
	}
	roll := usage.NewRollup()
	for rows.Next() {
		var raw string
		var en core.Entry
		if rows.Scan(&raw) == nil && json.Unmarshal([]byte(raw), &en) == nil {
			roll.Add(en)
		}
	}
	rows.Close()
	all, _ := roll.Metrics(ctx, usage.Query{By: usage.Dimensions})
	if len(all) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Totals that are already there counted these entries when they came.
	for _, r := range all {
		if err := addRow(ctx, tx, r, totals == 0); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Metrics answers a usage query from the hourly table.
func (e *Events) Metrics(ctx context.Context, q usage.Query) ([]usage.Row, error) {
	where := []string{"hour >= ?"}
	args := []any{q.From.UTC().Format(hourFormat)}
	if !q.To.IsZero() {
		where = append(where, "hour < ?")
		args = append(args, q.To.UTC().Format(hourFormat))
	}
	for col, v := range map[string]string{"project": q.Project, "env": q.Env, "token_id": q.TokenID, "service": q.Service, "model": q.Model, "operation": q.Operation, "saved_key": q.SavedKey} {
		if v != "" {
			where = append(where, col+" = ?")
			args = append(args, v)
		}
	}
	rows, err := e.db.ro.QueryContext(ctx, "SELECT "+strings.Join(usage.KeyColumns, ", ")+", "+strings.Join(usage.Columns, ", ")+
		" FROM metrics_hourly WHERE "+strings.Join(where, " AND "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []usage.Row
	for rows.Next() {
		var r usage.Row
		var hour string
		dst := []any{&hour, &r.Project, &r.Env, &r.TokenID, &r.Service, &r.Model, &r.Operation, &r.SavedKey}
		for _, p := range r.Counters() {
			dst = append(dst, p)
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		if r.Hour, err = time.Parse(hourFormat, hour); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return usage.Group(out, q.By), nil
}

// Totals returns the all-time counts by every dimension but the hour.
func (e *Events) Totals(ctx context.Context) ([]usage.Row, error) {
	rows, err := e.db.ro.QueryContext(ctx, "SELECT "+strings.Join(usage.KeyColumns[1:], ", ")+", "+strings.Join(usage.Columns, ", ")+" FROM metrics_total")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []usage.Row
	for rows.Next() {
		var r usage.Row
		dst := []any{&r.Project, &r.Env, &r.TokenID, &r.Service, &r.Model, &r.Operation, &r.SavedKey}
		for _, p := range r.Counters() {
			dst = append(dst, p)
		}
		if err := rows.Scan(dst...); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var (
	_ usage.Reader       = (*Events)(nil)
	_ usage.TotalsReader = (*Events)(nil)
)
