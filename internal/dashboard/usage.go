package dashboard

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/internal/usage"
)

// metrics is where usage comes from: Metrics if set, else the request log
// when it keeps hourly rows (both storages do).
func (s *Server) metrics() usage.Reader {
	if s.Metrics != nil {
		return s.Metrics
	}
	if r, ok := s.Log.(usage.Reader); ok {
		return r
	}
	return nil
}

var usageRanges = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// usageQuery reads ?range=, ?in= (an environment, "" for all) and ?by=.
// 24h is the last 24 hours; 7d and 30d are whole UTC days, today included.
func (s *Server) usageQuery(r *http.Request, defBy []string) (usage.Query, string) {
	rng := r.FormValue("range")
	d, ok := usageRanges[rng]
	if !ok {
		rng, d = "7d", usageRanges["7d"]
	}
	now := time.Now().UTC()
	step := time.Hour
	if rng != "24h" {
		step = 24 * time.Hour
	}
	// ?in= is the page's own filter ("" for all); arriving from the nav,
	// the environment picked elsewhere (?env=) is the filter.
	in := r.FormValue("in")
	if _, ok := r.Form["in"]; !ok {
		in = r.FormValue("env")
	}
	q := usage.Query{From: now.Truncate(step).Add(-d + step), Env: in}
	for _, b := range strings.Split(r.FormValue("by"), ",") {
		if slices.Contains(usage.Dimensions, b) && !slices.Contains(q.By, b) {
			q.By = append(q.By, b)
		}
	}
	if len(q.By) == 0 {
		q.By = defBy
	}
	return q, rng
}

// tokenNames maps every token ID to its name, for the page and exports.
func (s *Server) tokenNames() func(string) string {
	names := map[string]string{}
	for _, e := range s.Core.Environments() {
		for _, t := range s.Core.Tokens(e.ID) {
			names[t.ID] = t.Name
		}
	}
	return func(id string) string { return names[id] }
}

type usageRow struct {
	Label string
	Sub   string
	usage.ExportRow
	Errors int64
}

type usageBar struct {
	Label string
	Pct   int // of the busiest bar
	N     int64
}

type usageData struct {
	Range, By, In string
	Ranges        []string
	Bys           []string
	Envs          []string
	Rows          []usageRow
	Total         usageRow
	Bars          []usageBar
	BarsBy        string // "hour" or "day"
	Available     bool
	Query         string // range, in and by, for export links
}

func (s *Server) usagePage(w http.ResponseWriter, r *http.Request) {
	q, rng := s.usageQuery(r, []string{"service"})
	by := q.By[0]
	q.By = q.By[:1]
	d := usageData{Range: rng, By: by, In: q.Env, Ranges: []string{"24h", "7d", "30d"},
		Bys: []string{"service", "model", "token", "env", "project", "operation"}}
	for _, e := range s.Core.Environments() {
		d.Envs = append(d.Envs, e.ID)
	}
	mr := s.metrics()
	if mr != nil {
		d.Available = true
		rows, err := mr.Metrics(r.Context(), q)
		if err != nil {
			s.renderStatus(w, http.StatusInternalServerError, "usage", "Usage", "Couldn't read usage: "+err.Error(), d, s.env(r))
			return
		}
		names := s.tokenNames()
		var total usage.Row
		for i, x := range usage.Export(rows, names) {
			total.Merge(rows[i])
			row := usageRow{ExportRow: x, Errors: x.ClientErrors + x.UpstreamErrors + x.Unreachable}
			switch by {
			case "service":
				row.Label = x.Service
			case "model":
				row.Label, row.Sub = x.Model, x.Service
			case "token":
				row.Label, row.Sub = x.Token, x.TokenID
			case "env":
				row.Label = x.Env
			case "project":
				row.Label = x.Project
			case "operation":
				row.Label, row.Sub = x.Operation, x.Service
			}
			d.Rows = append(d.Rows, row)
		}
		t := usage.Export([]usage.Row{total}, nil)[0]
		d.Total = usageRow{Label: "Total", ExportRow: t, Errors: t.ClientErrors + t.UpstreamErrors + t.Unreachable}

		// Requests over time: by hour for a day, else by day, in UTC
		// like the hours stored.
		q.By = []string{"hour"}
		series, _ := mr.Metrics(r.Context(), q)
		step, format := time.Hour, "15:00 UTC"
		d.BarsBy = "hour"
		if rng != "24h" {
			step, format, d.BarsBy = 24*time.Hour, "2 Jan", "day"
		}
		counts := map[time.Time]int64{}
		for _, x := range series {
			counts[x.Hour.Truncate(step)] += x.Requests
		}
		var peak int64
		for t := q.From.Truncate(step); !t.After(time.Now().UTC()); t = t.Add(step) {
			d.Bars = append(d.Bars, usageBar{Label: t.Format(format), N: counts[t]})
			peak = max(peak, counts[t])
		}
		for i := range d.Bars {
			if peak > 0 {
				d.Bars[i].Pct = int(d.Bars[i].N * 100 / peak)
			}
		}
	}
	s.renderStatus(w, http.StatusOK, "usage", "Usage", "", d, s.env(r))
}

// usageExport serves usage as CSV or JSON: hourly rows with every
// dimension unless ?by= says otherwise.
func (s *Server) usageExport(w http.ResponseWriter, r *http.Request) {
	mr := s.metrics()
	if mr == nil {
		http.Error(w, "this storage keeps no usage metrics", http.StatusNotFound)
		return
	}
	q, rng := s.usageQuery(r, usage.Dimensions)
	rows, err := mr.Metrics(r.Context(), q)
	if err != nil {
		http.Error(w, "couldn't read usage", http.StatusInternalServerError)
		return
	}
	out := usage.Export(rows, s.tokenNames())
	name := "keystub-usage-" + rng + "-" + time.Now().UTC().Format("20060102")
	w.Header().Set("Cache-Control", "no-store")
	if r.FormValue("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		_ = usage.WriteJSON(w, out)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	_ = usage.WriteCSV(w, out)
}

// prometheus serves counters for Prometheus to scrape, with the admin
// token as a bearer token. They only go up: all time with SQLite, since
// start with the file log.
func (s *Server) prometheus(w http.ResponseWriter, r *http.Request) {
	tr, ok := s.metrics().(usage.TotalsReader)
	if !ok {
		http.Error(w, "this storage keeps no usage metrics", http.StatusNotFound)
		return
	}
	rows, err := tr.Totals(r.Context())
	if err == nil {
		rows = usage.Group(rows, []string{"project", "env", "service", "model", "operation"})
	}
	if err != nil {
		http.Error(w, "couldn't read usage", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_ = usage.WritePrometheus(w, rows)
}

// Template helpers for numbers.

func formatInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func formatUSD(usd float64) string {
	switch {
	case usd == 0:
		return "$0"
	case usd < 0.01:
		return "$" + strconv.FormatFloat(usd, 'f', 4, 64)
	default:
		return "$" + strconv.FormatFloat(usd, 'f', 2, 64)
	}
}

func percent(n, of int64) string {
	if of == 0 {
		return "—"
	}
	return strconv.FormatFloat(float64(n)*100/float64(of), 'f', 1, 64) + "%"
}
