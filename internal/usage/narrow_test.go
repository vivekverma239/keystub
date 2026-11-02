package usage

import (
	"net/http"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

func TestNarrow(t *testing.T) {
	for in, want := range map[string]string{
		"gzip, deflate, br, zstd": "gzip",
		"br":                      "",
		"identity;q=0, br":        "",
		"gzip;q=0, br":            "",
		"gzip;q=0.5, identity":    "gzip;q=0.5, identity",
		"GZIP; Q=0":               "",
	} {
		h := http.Header{"Accept-Encoding": {in}}
		Narrow("openai", h)
		if got := h.Get("Accept-Encoding"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	h := http.Header{"Accept-Encoding": {"br"}}
	Narrow("not-a-metered-service", h)
	if h.Get("Accept-Encoding") != "br" {
		t.Error("narrowed a service with no usage metadata")
	}
}

func TestOldEntriesKeepTheirOutcome(t *testing.T) {
	for _, c := range []struct {
		note string
		pick func(r *Row) int64
	}{
		{"upstream unreachable", func(r *Row) int64 { return r.Unreachable }},
		{"edge unreachable", func(r *Row) int64 { return r.Unreachable }},
		{"client went away", func(r *Row) int64 { return r.Canceled }},
		{"daily limit reached", func(r *Row) int64 { return r.Refused }},
	} {
		r := RowFor(core.Entry{Service: "openai", Status: 502, Note: c.note})
		if c.pick(&r) != 1 {
			t.Errorf("%q: %+v", c.note, r)
		}
	}
}

// Header values are trimmed of HTTP whitespace only, as the edge trims
// them: a no-break space is part of the value, so it isn't a number.
func TestHeaderWhitespace(t *testing.T) {
	for in, want := range map[string]int64{" 7\t": 7, "7 ": -1, "7,9": 7} {
		m := Start("openai", "POST", "/v1/chat/completions", time.Now())
		m.Response(&http.Response{StatusCode: 429, Header: http.Header{"X-Ratelimit-Remaining-Requests": {in}}, Body: http.NoBody})
		var e core.Entry
		m.Finish(&e)
		got := int64(-1)
		if e.Quota != nil && e.Quota.RequestsLeft != nil {
			got = *e.Quota.RequestsLeft
		}
		if got != want {
			t.Errorf("%q: requests left %d, want %d", in, got, want)
		}
	}
}

// The same table as the edge's "dot segments" test.
func TestRemoveDotSegments(t *testing.T) {
	for in, want := range map[string]string{
		"/v1/chat/completions":        "/v1/chat/completions",
		"/v1/x/../chat/./completions": "/v1/chat/completions",
		"/a/b/..":                     "/a/",
		"/a/.":                        "/a/",
		"/..":                         "/",
		"/../../a":                    "/a",
		"/a/v1.5/b":                   "/a/v1.5/b",
	} {
		if got := removeDotSegments(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
