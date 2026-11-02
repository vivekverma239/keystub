// Package sqlite keeps everything Keystub stores in one SQLite file: the
// model (a core.Repository), limit counts (a core.Limiter, so they survive
// restarts) and the request log (a core.Sink and core.LogReader).
//
// Model rows are stored as JSON next to their keys, so new fields need no
// schema change.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no cgo
)

const schema = `
CREATE TABLE IF NOT EXISTS projects     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS environments (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS keys         (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS links        (env_id TEXT NOT NULL, service_id TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (env_id, service_id));
CREATE TABLE IF NOT EXISTS tokens       (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS machines     (id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS counters     (key TEXT PRIMARY KEY, day TEXT NOT NULL, day_count INTEGER NOT NULL, minute TEXT NOT NULL, min_count INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events       (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
`

// DB is an open Keystub database.
type DB struct {
	db    *sql.DB // the one connection that writes, and reads on the request path
	ro    *sql.DB // read-only connections for the dashboard's bigger reads
	notes []string
}

// Open opens (or creates) the database at path. The file holds sealed keys
// and token hashes, so it is readable by its owner only; SQLite gives its
// -wal and -shm files the same mode.
func Open(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(abs, 0o600); err != nil {
		return nil, err
	}
	// A URI escapes the path, so "?", "#" or "%" in it can't be read as
	// parameters.
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs),
		RawQuery: "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// One connection: SQLite takes one writer at a time anyway, and this
	// keeps limit checks strictly in order.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := ensureMetrics(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	notes, err := convert(db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("convert %s: %w", path, err)
	}
	// WAL lets these read while the writer writes, so a usage page over a
	// month of rows never holds up a limit check or a log write.
	u.RawQuery = "mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)"
	ro, err := sql.Open("sqlite", u.String())
	if err != nil {
		db.Close()
		return nil, err
	}
	ro.SetMaxOpenConns(4)
	return &DB{db: db, ro: ro, notes: notes}, nil
}

// Notes says what converting an older database changed that someone
// should know: tokens that now reach more services.
func (d *DB) Notes() []string { return d.notes }

// convert brings a database from before saved keys up to date, in one
// transaction: each row of the old bindings table becomes a saved key named
// "<env> <service>" and a link, and the table is dropped; each token with
// no kind is upgraded (see core.OldToken.Upgrade).
func convert(db *sql.DB) (notes []string, err error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'bindings'").Scan(&n); err != nil {
		return nil, err
	}
	if n > 0 {
		var bs []core.Binding
		rows, err := tx.Query("SELECT data FROM bindings ORDER BY rowid")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw string
			var b core.Binding
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, err
			}
			if err := json.Unmarshal([]byte(raw), &b); err != nil {
				rows.Close()
				return nil, fmt.Errorf("bindings: %w", err)
			}
			bs = append(bs, b)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, b := range bs {
			k, l := core.FromBinding(b)
			// An environment that links a key already (bindings made again
			// by an older build) keeps its link, and no key is left over.
			res, err := tx.Exec("INSERT INTO links (env_id, service_id, data) VALUES (?, ?, ?) ON CONFLICT(env_id, service_id) DO NOTHING", l.EnvID, l.ServiceID, mustJSON(l))
			if err != nil {
				return nil, err
			}
			if n, err := res.RowsAffected(); err != nil || n == 0 {
				notes = append(notes, fmt.Sprintf("an old real key for %s in %s was dropped: the environment already links a saved key for it", b.ServiceID, b.EnvID))
				continue
			}
			if _, err := tx.Exec("INSERT INTO keys (id, data) VALUES (?, ?)", k.ID, mustJSON(k)); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec("DROP TABLE bindings"); err != nil {
			return nil, err
		}
	}
	// A build from before saved keys reads and writes "bindings"; this
	// view, which has no such columns, makes it fail at start instead of
	// running without the saved keys.
	if _, err := tx.Exec(`CREATE VIEW IF NOT EXISTS bindings AS SELECT 'converted to saved keys and links by a newer Keystub; this build is older than this database' AS converted`); err != nil {
		return nil, err
	}
	rows, err := tx.Query("SELECT id, data FROM tokens WHERE json_extract(data, '$.kind') IS NULL OR json_extract(data, '$.kind') = ''")
	if err != nil {
		return nil, err
	}
	var olds []core.OldToken
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		var ot core.OldToken
		if err := json.Unmarshal([]byte(raw), &ot); err != nil {
			rows.Close()
			return nil, fmt.Errorf("tokens: %w", err)
		}
		olds = append(olds, ot)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ups, tokNotes := core.UpgradeTokens(olds, time.Now())
	notes = append(notes, tokNotes...)
	for _, t := range ups {
		if _, err := tx.Exec("UPDATE tokens SET data = ? WHERE id = ?", mustJSON(t), t.ID); err != nil {
			return nil, err
		}
	}
	return notes, tx.Commit()
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // the model's types always marshal
	}
	return string(b)
}

// Close closes the database.
func (d *DB) Close() error {
	d.ro.Close()
	return d.db.Close()
}

// --- core.Repository ---

func list[T any](ctx context.Context, d *DB, table string) ([]T, error) {
	rows, err := d.db.QueryContext(ctx, "SELECT data FROM "+table+" ORDER BY rowid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("%s: %w", table, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func put(ctx context.Context, d *DB, table, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = d.db.ExecContext(ctx, "INSERT INTO "+table+" (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data", id, string(b))
	return err
}

func deleted(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return core.ErrNotFound
	}
	return nil
}

func (d *DB) ListProjects(ctx context.Context) ([]core.Project, error) {
	return list[core.Project](ctx, d, "projects")
}

func (d *DB) PutProject(ctx context.Context, p core.Project) error {
	return put(ctx, d, "projects", p.ID, p)
}

func (d *DB) ListEnvironments(ctx context.Context) ([]core.Environment, error) {
	return list[core.Environment](ctx, d, "environments")
}

func (d *DB) PutEnvironment(ctx context.Context, e core.Environment) error {
	return put(ctx, d, "environments", e.ID, e)
}

func (d *DB) DeleteEnvironment(ctx context.Context, id string) error {
	return deleted(d.db.ExecContext(ctx, "DELETE FROM environments WHERE id = ?", id))
}

func (d *DB) ListServices(ctx context.Context) ([]core.Service, error) {
	return list[core.Service](ctx, d, "services")
}

func (d *DB) PutService(ctx context.Context, s core.Service) error {
	return put(ctx, d, "services", s.ID, s)
}

func (d *DB) DeleteService(ctx context.Context, id string) error {
	return deleted(d.db.ExecContext(ctx, "DELETE FROM services WHERE id = ?", id))
}

func (d *DB) ListKeys(ctx context.Context) ([]core.SavedKey, error) {
	return list[core.SavedKey](ctx, d, "keys")
}

func (d *DB) PutKey(ctx context.Context, k core.SavedKey) error {
	return put(ctx, d, "keys", k.ID, k)
}

func (d *DB) DeleteKey(ctx context.Context, id string) error {
	return deleted(d.db.ExecContext(ctx, "DELETE FROM keys WHERE id = ?", id))
}

func (d *DB) ListLinks(ctx context.Context) ([]core.Link, error) {
	return list[core.Link](ctx, d, "links")
}

func (d *DB) PutLink(ctx context.Context, l core.Link) error {
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = d.db.ExecContext(ctx, "INSERT INTO links (env_id, service_id, data) VALUES (?, ?, ?) ON CONFLICT(env_id, service_id) DO UPDATE SET data = excluded.data", l.EnvID, l.ServiceID, string(raw))
	return err
}

func (d *DB) DeleteLink(ctx context.Context, envID, serviceID string) error {
	return deleted(d.db.ExecContext(ctx, "DELETE FROM links WHERE env_id = ? AND service_id = ?", envID, serviceID))
}

func (d *DB) ListTokens(ctx context.Context) ([]core.Token, error) {
	return list[core.Token](ctx, d, "tokens")
}

func (d *DB) PutToken(ctx context.Context, t core.Token) error {
	return put(ctx, d, "tokens", t.ID, t)
}

func (d *DB) ListMachines(ctx context.Context) ([]core.Machine, error) {
	return list[core.Machine](ctx, d, "machines")
}

func (d *DB) PutMachine(ctx context.Context, m core.Machine) error {
	return put(ctx, d, "machines", m.ID, m)
}

// Empty reports whether the database holds no projects yet.
func (d *DB) Empty(ctx context.Context) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx, "SELECT count(*) FROM projects").Scan(&n)
	return n == 0, err
}

// Import copies everything from another repository, in one transaction, so
// a switch from the JSON file to SQLite keeps every key and token.
func (d *DB) Import(ctx context.Context, from core.Repository) (err error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	ins := func(table string, args ...any) error {
		q := "INSERT INTO " + table + " (id, data) VALUES (?, ?)"
		if table == "links" {
			q = "INSERT INTO links (env_id, service_id, data) VALUES (?, ?, ?)"
		}
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	j := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	ps, err := from.ListProjects(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if err := ins("projects", p.ID, j(p)); err != nil {
			return err
		}
	}
	es, err := from.ListEnvironments(ctx)
	if err != nil {
		return err
	}
	for _, e := range es {
		if err := ins("environments", e.ID, j(e)); err != nil {
			return err
		}
	}
	ss, err := from.ListServices(ctx)
	if err != nil {
		return err
	}
	for _, s := range ss {
		if err := ins("services", s.ID, j(s)); err != nil {
			return err
		}
	}
	ks, err := from.ListKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range ks {
		if err := ins("keys", k.ID, j(k)); err != nil {
			return err
		}
	}
	ls, err := from.ListLinks(ctx)
	if err != nil {
		return err
	}
	for _, l := range ls {
		if err := ins("links", l.EnvID, l.ServiceID, j(l)); err != nil {
			return err
		}
	}
	ts, err := from.ListTokens(ctx)
	if err != nil {
		return err
	}
	for _, t := range ts {
		if err := ins("tokens", t.ID, j(t)); err != nil {
			return err
		}
	}
	ms, err := from.ListMachines(ctx)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if err := ins("machines", m.ID, j(m)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var _ core.Repository = (*DB)(nil)
