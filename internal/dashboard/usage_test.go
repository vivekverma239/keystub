package dashboard

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

func TestUsagePagesAndExports(t *testing.T) {
	s, st := newServer(t)
	_, tok, err := st.CreateToken(bg, core.TokenSpec{EnvID: dev, Name: "ci-bot"})
	if err != nil {
		t.Fatal(err)
	}
	cost := int64(1_250_000)
	lg := s.Log.(interface{ Add(core.Entry) })
	now := time.Now().UTC()
	lg.Add(core.Entry{Time: now, Project: "default", Env: dev, TokenID: tok.ID, Key: "ci-bot", Service: "openai", Model: "gpt-6-sol", Operation: "chat",
		Status: 200, Outcome: core.OutcomeOK, DurationMs: 800, Usage: &core.Usage{InputTokens: 1234, OutputTokens: 56}, CostMicros: &cost})
	lg.Add(core.Entry{Time: now, Project: "default", Env: dev, TokenID: tok.ID, Service: "openai", Model: "=HYPERLINK(1)", Status: 401, Outcome: core.OutcomeKeyRejected})

	if w := do(s, "GET", "/usage", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	w := do(s, "GET", "/usage?range=24h&by=token", "", cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ci-bot") || !strings.Contains(w.Body.String(), "1,234") || !strings.Contains(w.Body.String(), "$1.25") {
		t.Fatalf("page %d: %s", w.Code, w.Body.String())
	}

	// The page's export links keep its range and environment.
	w = do(s, "GET", "/usage?range=24h&in="+dev, "", cookie)
	if want := `/usage/export?format=csv&range=24h&in=` + strings.ReplaceAll(dev, "/", "%2f") + `"`; !strings.Contains(w.Body.String(), want) {
		t.Fatalf("export link isn't %s: %s", want, w.Body.String())
	}
	// The nav's environment is the filter when the page has none of its
	// own; "All environments" clears it.
	w = do(s, "GET", "/usage?range=24h&env="+dev, "", cookie)
	if want := `&in=` + strings.ReplaceAll(dev, "/", "%2f") + `"`; !strings.Contains(w.Body.String(), want) {
		t.Fatalf("the nav's environment was ignored: %s", w.Body.String())
	}
	w = do(s, "GET", "/usage?range=24h&env="+dev+"&in=", "", cookie)
	if !strings.Contains(w.Body.String(), `class="on">All environments`) {
		t.Fatalf("in= doesn't mean all: %s", w.Body.String())
	}
	// 7 days are 7 whole UTC days, labelled in UTC.
	w = do(s, "GET", "/usage?range=7d", "", cookie)
	if n := strings.Count(w.Body.String(), `class="bar"`); n != 7 {
		t.Fatalf("%d bars for 7 days", n)
	}
	if !strings.Contains(w.Body.String(), now.Format("2 Jan")+": 2 requests") {
		t.Fatalf("today's bar isn't labelled %s in UTC: %s", now.Format("2 Jan"), w.Body.String())
	}

	w = do(s, "GET", "/usage/export?format=csv&range=24h", "", admin)
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(recs) != 3 || recs[0][0] != "hour" {
		t.Fatalf("csv %v: %q", err, w.Body.String())
	}
	var sawFormula bool
	for _, r := range recs[1:] {
		if r[4] != "ci-bot" {
			t.Fatalf("token name missing: %v", r)
		}
		sawFormula = sawFormula || r[6] == "'=HYPERLINK(1)"
	}
	if !sawFormula {
		t.Fatalf("a formula-looking cell wasn't defused: %v", recs)
	}

	w = do(s, "GET", "/usage/export?format=json&range=24h&by=service", "", admin)
	var out struct {
		Rows []struct {
			Service     string  `json:"service"`
			Requests    int64   `json:"requests"`
			KeyRejected int64   `json:"keyRejected"`
			CostUSD     float64 `json:"costUsd"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Rows) != 1 || out.Rows[0].Requests != 2 || out.Rows[0].KeyRejected != 1 || out.Rows[0].CostUSD != 1.25 {
		t.Fatalf("json %v: %s", err, w.Body.String())
	}

	if w := do(s, "GET", "/metrics", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without a token: %d", w.Code)
	}
	w = do(s, "GET", "/metrics", "", admin)
	body := w.Body.String()
	for _, want := range []string{
		`keystub_requests_total{project="default",env="default/dev",service="openai",model="gpt-6-sol",operation="chat",outcome="ok"} 1`,
		`outcome="key_rejected"} 1`,
		`kind="input"} 1234`,
		`keystub_cost_usd_total{project="default",env="default/dev",service="openai",model="gpt-6-sol",operation="chat"} 1.250000`,
		`le="+Inf"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q:\n%s", want, body)
		}
	}
}
