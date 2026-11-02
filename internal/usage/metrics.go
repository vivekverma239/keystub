package usage

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// Buckets are the upper bounds, in milliseconds, of the latency histogram
// each metrics row keeps; a last bucket holds everything slower. The
// hosted platform uses the same bounds, so rows add up the same anywhere.
var Buckets = [...]int64{10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500, 10000, 20000, 60000}

// NumBuckets is len(Buckets) plus the open last bucket.
const NumBuckets = len(Buckets) + 1

// BucketColumn names a histogram bucket's column: lat_10 … lat_60000, lat_inf.
func BucketColumn(i int) string {
	if i == len(Buckets) {
		return "lat_inf"
	}
	return "lat_" + strconv.FormatInt(Buckets[i], 10)
}

// Key is one row of the hourly metrics table.
type Key struct {
	Hour      time.Time `json:"hour"`
	Project   string    `json:"project"`
	Env       string    `json:"env"`
	TokenID   string    `json:"tokenId"`
	Service   string    `json:"service"`
	Model     string    `json:"model"`
	Operation string    `json:"operation"`
	SavedKey  string    `json:"savedKey"` // the saved key's ID
}

// Row is what the requests with one Key added up to in one hour. Every
// field adds, so rows merge by summing: by hour, by token, or across
// several data planes.
type Row struct {
	Key
	Requests       int64 `json:"requests"`
	OK             int64 `json:"ok"`
	ClientErrors   int64 `json:"clientErrors"`
	KeyRejected    int64 `json:"keyRejected"`
	RateLimited    int64 `json:"rateLimited"`
	UpstreamErrors int64 `json:"upstreamErrors"`
	Unreachable    int64 `json:"unreachable"`
	Refused        int64 `json:"refused"`
	Canceled       int64 `json:"canceled"`

	InputTokens      int64 `json:"inputTokens"`
	CachedTokens     int64 `json:"cachedTokens"`
	CacheWriteTokens int64 `json:"cacheWriteTokens"`
	OutputTokens     int64 `json:"outputTokens"`
	Units            int64 `json:"units"`
	CostMicros       int64 `json:"costMicros"`
	Unpriced         int64 `json:"unpriced"` // requests with usage but no known price

	DurationMsSum int64             `json:"durationMsSum"`
	OverheadMsSum int64             `json:"overheadMsSum"` // Keystub's own time, requests that went upstream
	Latency       [NumBuckets]int64 `json:"latency"`
}

// RowFor is one entry's contribution to its hour's row.
func RowFor(e core.Entry) Row {
	r := Row{Key: Key{Hour: e.Time.UTC().Truncate(time.Hour), Project: e.Project, Env: e.Env, TokenID: e.TokenID,
		Service: e.Service, Model: e.Model, Operation: e.Operation, SavedKey: e.SavedKey}, Requests: 1}
	o := e.Outcome
	if o == "" { // entries from before outcomes were recorded
		switch e.Note {
		case "upstream unreachable", "edge unreachable":
			o = core.OutcomeUnreachable
		case "client went away":
			o = core.OutcomeCanceled
		default:
			o = Outcome(e.Service, e.Status, e.Note)
		}
	}
	*r.outcome(o) = 1
	if u := e.Usage; u != nil {
		r.InputTokens, r.CachedTokens, r.CacheWriteTokens, r.OutputTokens, r.Units = u.InputTokens, u.CachedTokens, u.CacheWriteTokens, u.OutputTokens, u.Units
		if e.CostMicros == nil {
			r.Unpriced = 1
		}
	}
	if e.CostMicros != nil {
		r.CostMicros = *e.CostMicros
	}
	d := max(e.DurationMs, 0)
	r.DurationMsSum = d
	if r.Refused == 0 {
		r.OverheadMsSum = max(e.OverheadMs, 0)
	}
	r.Latency[bucketOf(d)] = 1
	return r
}

// outcome is the counter an outcome adds to; anything unknown is a client
// error.
func (r *Row) outcome(o string) *int64 {
	switch o {
	case core.OutcomeOK:
		return &r.OK
	case core.OutcomeKeyRejected:
		return &r.KeyRejected
	case core.OutcomeRateLimited:
		return &r.RateLimited
	case core.OutcomeUpstreamError:
		return &r.UpstreamErrors
	case core.OutcomeUnreachable:
		return &r.Unreachable
	case core.OutcomeRefused:
		return &r.Refused
	case core.OutcomeCanceled:
		return &r.Canceled
	default:
		return &r.ClientErrors
	}
}

func bucketOf(ms int64) int {
	for i, b := range Buckets {
		if ms <= b {
			return i
		}
	}
	return len(Buckets)
}

// Merge adds o's counts into r. Keys are left alone.
func (r *Row) Merge(o Row) {
	for i, p := range r.counters() {
		*p += *o.counters()[i]
	}
}

// counters lists every additive field, in Columns order.
func (r *Row) counters() []*int64 {
	out := []*int64{&r.Requests, &r.OK, &r.ClientErrors, &r.KeyRejected, &r.RateLimited, &r.UpstreamErrors, &r.Unreachable, &r.Refused, &r.Canceled,
		&r.InputTokens, &r.CachedTokens, &r.CacheWriteTokens, &r.OutputTokens, &r.Units, &r.CostMicros, &r.Unpriced,
		&r.DurationMsSum, &r.OverheadMsSum}
	for i := range r.Latency {
		out = append(out, &r.Latency[i])
	}
	return out
}

// Counters returns pointers to every additive field, in Columns order, for
// storage adapters to scan into and write from.
func (r *Row) Counters() []*int64 { return r.counters() }

// Columns are the additive columns of the metrics table, in Counters order.
// The key columns come first: hour, project, env, token_id, service,
// model, operation.
var Columns = func() []string {
	c := []string{"requests", "ok", "client_errors", "key_rejected", "rate_limited", "upstream_errors", "unreachable", "refused", "canceled",
		"input_tokens", "cached_tokens", "cache_write_tokens", "output_tokens", "units", "cost_micros", "unpriced",
		"duration_ms_sum", "overhead_ms_sum"}
	for i := 0; i < NumBuckets; i++ {
		c = append(c, BucketColumn(i))
	}
	return c
}()

// KeyColumns are the metrics table's key columns, in Key order.
var KeyColumns = []string{"hour", "project", "env", "token_id", "service", "model", "operation", "saved_key"}

// Percentile estimates the p-th latency percentile (0 < p ≤ 1) in ms from
// the histogram, interpolating within the bucket it falls in.
func (r Row) Percentile(p float64) int64 {
	var total int64
	for _, n := range r.Latency {
		total += n
	}
	if total == 0 {
		return 0
	}
	rank := p * float64(total)
	var seen int64
	for i, n := range r.Latency {
		if n == 0 {
			continue
		}
		if float64(seen+n) >= rank {
			lo := int64(0)
			if i > 0 {
				lo = Buckets[i-1]
			}
			if i == len(Buckets) {
				return lo // the open bucket has no top
			}
			frac := (rank - float64(seen)) / float64(n)
			return lo + int64(frac*float64(Buckets[i]-lo)+0.5)
		}
		seen += n
	}
	return Buckets[len(Buckets)-1]
}

// AvgMs and OverheadAvgMs are mean latencies; Keystub's own time counts
// only requests that went upstream.
func (r Row) AvgMs() int64 {
	if r.Requests == 0 {
		return 0
	}
	return r.DurationMsSum / r.Requests
}

func (r Row) OverheadAvgMs() int64 {
	n := r.Requests - r.Refused
	if n <= 0 {
		return 0
	}
	return r.OverheadMsSum / n
}

// Query picks metrics rows: hours in [From, To), matching every filter
// that isn't empty, grouped by the dimensions in By (the others are
// summed over and left empty).
type Query struct {
	From, To                                         time.Time
	Project, Env, TokenID, Service, Model, Operation string
	SavedKey                                         string
	By                                               []string // of Dimensions
}

// Dimensions are what a Query can group by; "key" is the saved key.
var Dimensions = []string{"hour", "project", "env", "token", "service", "model", "operation", "key"}

// Matches reports whether a row's key passes the query's filters.
func (q Query) Matches(k Key) bool {
	return !k.Hour.Before(q.From) && (q.To.IsZero() || k.Hour.Before(q.To)) &&
		(q.Project == "" || k.Project == q.Project) && (q.Env == "" || k.Env == q.Env) &&
		(q.TokenID == "" || k.TokenID == q.TokenID) && (q.Service == "" || k.Service == q.Service) &&
		(q.Model == "" || k.Model == q.Model) && (q.Operation == "" || k.Operation == q.Operation) &&
		(q.SavedKey == "" || k.SavedKey == q.SavedKey)
}

// Group sums rows by the dimensions in by, newest hour first, then by
// cost and requests.
func Group(rows []Row, by []string) []Row {
	keep := func(d string) bool { return slices.Contains(by, d) }
	m := map[Key]*Row{}
	var order []Key
	for _, r := range rows {
		k := r.Key
		if !keep("hour") {
			k.Hour = time.Time{}
		}
		if !keep("project") {
			k.Project = ""
		}
		if !keep("env") {
			k.Env = ""
		}
		if !keep("token") {
			k.TokenID = ""
		}
		if !keep("service") {
			k.Service = ""
		}
		if !keep("model") {
			k.Model = ""
		}
		if !keep("operation") {
			k.Operation = ""
		}
		if !keep("key") {
			k.SavedKey = ""
		}
		g, ok := m[k]
		if !ok {
			g = &Row{Key: k}
			m[k] = g
			order = append(order, k)
		}
		g.Merge(r)
	}
	out := make([]Row, 0, len(order))
	for _, k := range order {
		out = append(out, *m[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Hour.Equal(b.Hour) {
			return a.Hour.After(b.Hour)
		}
		if a.CostMicros != b.CostMicros {
			return a.CostMicros > b.CostMicros
		}
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return fmt.Sprint(a.Key) < fmt.Sprint(b.Key)
	})
	return out
}

// Reader returns metrics rows. The SQLite store and the file log provide it.
type Reader interface {
	Metrics(ctx context.Context, q Query) ([]Row, error)
}

// TotalsReader returns all-time counts by every dimension but the hour,
// which only ever go up: what /metrics serves.
type TotalsReader interface {
	Totals(ctx context.Context) ([]Row, error)
}

// Rollup keeps hourly rows in memory: the file log's metrics, rebuilt from
// its file at start.
type Rollup struct {
	mu        sync.Mutex
	rows      map[Key]*Row
	allTime   bool
	keep      time.Duration // hours older than this before the newest go; 0 keeps all
	lastPrune time.Time
}

// NewRollup returns an empty rollup that keeps every hour.
func NewRollup() *Rollup { return &Rollup{rows: map[Key]*Row{}} }

// NewRollupKeeping returns an empty rollup that drops hours more than keep
// before the newest entry, checking at most once an hour, so a long-running
// process holds a bounded number of rows.
func NewRollupKeeping(keep time.Duration) *Rollup {
	return &Rollup{rows: map[Key]*Row{}, keep: keep}
}

// NewTotals returns an empty rollup that keeps no hours: one row per key
// for all time, as a TotalsReader.
func NewTotals() *Rollup { return &Rollup{rows: map[Key]*Row{}, allTime: true} }

// Totals returns every row; for a NewTotals rollup, the all-time counts.
func (r *Rollup) Totals(ctx context.Context) ([]Row, error) {
	return r.Metrics(ctx, Query{By: Dimensions})
}

// Add counts an entry.
func (r *Rollup) Add(e core.Entry) {
	row := RowFor(e)
	if r.allTime {
		row.Hour = time.Time{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.rows[row.Key]; ok {
		g.Merge(row)
	} else {
		r.rows[row.Key] = &row
	}
	if r.keep > 0 && row.Hour.Sub(r.lastPrune) >= time.Hour {
		// Never from a time ahead of the clock: one entry stamped in the
		// future mustn't prune every real hour, nor stop pruning after.
		newest := row.Hour
		if now := time.Now().UTC().Truncate(time.Hour); newest.After(now) {
			newest = now
		}
		r.lastPrune = newest
		before := newest.Add(-r.keep)
		for k := range r.rows {
			if k.Hour.Before(before) {
				delete(r.rows, k)
			}
		}
	}
}

// Metrics answers a query. It copies only the matching rows under the
// lock; grouping them happens after.
func (r *Rollup) Metrics(_ context.Context, q Query) ([]Row, error) {
	r.mu.Lock()
	var rows []Row
	for k, v := range r.rows {
		if q.Matches(k) {
			rows = append(rows, *v)
		}
	}
	r.mu.Unlock()
	return Group(rows, q.By), nil
}

// ExportRow is a row as CSV and JSON exports write it: counts plus the
// derived latencies, cost in dollars, and the token's name.
type ExportRow struct {
	Hour           string  `json:"hour,omitempty"`
	Project        string  `json:"project,omitempty"`
	Env            string  `json:"env,omitempty"`
	TokenID        string  `json:"tokenId,omitempty"`
	Token          string  `json:"token,omitempty"`
	Service        string  `json:"service,omitempty"`
	Model          string  `json:"model,omitempty"`
	Operation      string  `json:"operation,omitempty"`
	Key            string  `json:"key,omitempty"` // the saved key's ID
	Requests       int64   `json:"requests"`
	OK             int64   `json:"ok"`
	ClientErrors   int64   `json:"clientErrors"`
	KeyRejected    int64   `json:"keyRejected"`
	RateLimited    int64   `json:"rateLimited"`
	UpstreamErrors int64   `json:"upstreamErrors"`
	Unreachable    int64   `json:"unreachable"`
	Refused        int64   `json:"refused"`
	Canceled       int64   `json:"canceled"`
	InputTokens    int64   `json:"inputTokens"`
	CachedTokens   int64   `json:"cachedTokens"`
	CacheWrite     int64   `json:"cacheWriteTokens"`
	OutputTokens   int64   `json:"outputTokens"`
	Units          int64   `json:"units"`
	CostUSD        float64 `json:"costUsd"`
	Unpriced       int64   `json:"unpriced"`
	P50Ms          int64   `json:"p50Ms"`
	P95Ms          int64   `json:"p95Ms"`
	AvgMs          int64   `json:"avgMs"`
	KeystubAvgMs   int64   `json:"keystubAvgMs"`
}

// Export turns rows into export rows; tokenName names token IDs.
func Export(rows []Row, tokenName func(id string) string) []ExportRow {
	out := make([]ExportRow, 0, len(rows))
	for _, r := range rows {
		e := ExportRow{Project: r.Project, Env: r.Env, TokenID: r.TokenID, Service: r.Service, Model: r.Model, Operation: r.Operation, Key: r.SavedKey,
			Requests: r.Requests, OK: r.OK, ClientErrors: r.ClientErrors, KeyRejected: r.KeyRejected, RateLimited: r.RateLimited,
			UpstreamErrors: r.UpstreamErrors, Unreachable: r.Unreachable, Refused: r.Refused, Canceled: r.Canceled,
			InputTokens: r.InputTokens, CachedTokens: r.CachedTokens, CacheWrite: r.CacheWriteTokens, OutputTokens: r.OutputTokens, Units: r.Units,
			CostUSD: float64(r.CostMicros) / 1e6, Unpriced: r.Unpriced,
			P50Ms: r.Percentile(0.5), P95Ms: r.Percentile(0.95), AvgMs: r.AvgMs(), KeystubAvgMs: r.OverheadAvgMs()}
		if !r.Hour.IsZero() {
			e.Hour = r.Hour.UTC().Format(time.RFC3339)
		}
		if r.TokenID != "" && tokenName != nil {
			e.Token = tokenName(r.TokenID)
		}
		out = append(out, e)
	}
	return out
}

var csvHeader = []string{"hour", "project", "env", "token_id", "token", "service", "model", "operation",
	"requests", "ok", "client_errors", "key_rejected", "rate_limited", "upstream_errors", "unreachable", "refused", "canceled",
	"input_tokens", "cached_tokens", "cache_write_tokens", "output_tokens", "units", "cost_usd", "unpriced",
	"p50_ms", "p95_ms", "avg_ms", "keystub_avg_ms", "key"}

// WriteCSV writes export rows as CSV with a header line. Text cells that a
// spreadsheet would run as a formula are quoted with a leading '.
func WriteCSV(w io.Writer, rows []ExportRow) error {
	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader)
	i := func(n int64) string { return strconv.FormatInt(n, 10) }
	for _, r := range rows {
		_ = cw.Write([]string{r.Hour, cell(r.Project), cell(r.Env), cell(r.TokenID), cell(r.Token), cell(r.Service), cell(r.Model), cell(r.Operation),
			i(r.Requests), i(r.OK), i(r.ClientErrors), i(r.KeyRejected), i(r.RateLimited), i(r.UpstreamErrors), i(r.Unreachable), i(r.Refused), i(r.Canceled),
			i(r.InputTokens), i(r.CachedTokens), i(r.CacheWrite), i(r.OutputTokens), i(r.Units),
			strconv.FormatFloat(r.CostUSD, 'f', 6, 64), i(r.Unpriced), i(r.P50Ms), i(r.P95Ms), i(r.AvgMs), i(r.KeystubAvgMs), cell(r.Key)})
	}
	cw.Flush()
	return cw.Error()
}

func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// WriteJSON writes export rows as a JSON object {"rows": [...]}.
func WriteJSON(w io.Writer, rows []ExportRow) error {
	return json.NewEncoder(w).Encode(map[string]any{"rows": rows})
}

// WritePrometheus writes rows as Prometheus counters and a latency
// histogram, in the text exposition format. Rows should be all-time totals
// (Query with no From), so the counters only go up.
func WritePrometheus(w io.Writer, rows []Row) error {
	var b strings.Builder
	labels := func(r Row, extra ...string) string {
		kv := []string{"project", r.Project, "env", r.Env, "service", r.Service, "model", r.Model, "operation", r.Operation}
		kv = append(kv, extra...)
		var parts []string
		for i := 0; i < len(kv); i += 2 {
			parts = append(parts, kv[i]+`="`+promEscape(kv[i+1])+`"`)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	head := func(name, typ, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	head("keystub_requests_total", "counter", "Requests through Keystub, by outcome.")
	for _, r := range rows {
		for _, o := range []struct {
			name string
			n    int64
		}{{core.OutcomeOK, r.OK}, {core.OutcomeClientError, r.ClientErrors}, {core.OutcomeKeyRejected, r.KeyRejected}, {core.OutcomeRateLimited, r.RateLimited},
			{core.OutcomeUpstreamError, r.UpstreamErrors}, {core.OutcomeUnreachable, r.Unreachable}, {core.OutcomeRefused, r.Refused}, {core.OutcomeCanceled, r.Canceled}} {
			if o.n > 0 {
				fmt.Fprintf(&b, "keystub_requests_total%s %d\n", labels(r, "outcome", o.name), o.n)
			}
		}
	}
	head("keystub_tokens_total", "counter", "Tokens the services reported. input includes cached and cache_write.")
	for _, r := range rows {
		for _, t := range []struct {
			kind string
			n    int64
		}{{"input", r.InputTokens}, {"cached", r.CachedTokens}, {"cache_write", r.CacheWriteTokens}, {"output", r.OutputTokens}} {
			if t.n > 0 {
				fmt.Fprintf(&b, "keystub_tokens_total%s %d\n", labels(r, "kind", t.kind), t.n)
			}
		}
	}
	head("keystub_units_total", "counter", "Units the services reported where they don't count tokens.")
	for _, r := range rows {
		if r.Units > 0 {
			fmt.Fprintf(&b, "keystub_units_total%s %d\n", labels(r), r.Units)
		}
	}
	head("keystub_cost_usd_total", "counter", "Cost in US dollars, from the services' reports or list prices.")
	for _, r := range rows {
		if r.CostMicros > 0 {
			fmt.Fprintf(&b, "keystub_cost_usd_total%s %s\n", labels(r), strconv.FormatFloat(float64(r.CostMicros)/1e6, 'f', 6, 64))
		}
	}
	head("keystub_request_duration_seconds", "histogram", "Request duration, to the end of the response.")
	for _, r := range rows {
		var cum int64
		for i, n := range r.Latency {
			cum += n
			le := "+Inf"
			if i < len(Buckets) {
				le = strconv.FormatFloat(float64(Buckets[i])/1000, 'f', -1, 64)
			}
			fmt.Fprintf(&b, "keystub_request_duration_seconds_bucket%s %d\n", labels(r, "le", le), cum)
		}
		fmt.Fprintf(&b, "keystub_request_duration_seconds_sum%s %s\n", labels(r), strconv.FormatFloat(float64(r.DurationMsSum)/1000, 'f', 3, 64))
		fmt.Fprintf(&b, "keystub_request_duration_seconds_count%s %d\n", labels(r), r.Requests)
	}
	head("keystub_overhead_seconds_total", "counter", "Keystub's own time before requests went upstream.")
	for _, r := range rows {
		fmt.Fprintf(&b, "keystub_overhead_seconds_total%s %s\n", labels(r), strconv.FormatFloat(float64(r.OverheadMsSum)/1000, 'f', 3, 64))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func promEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
