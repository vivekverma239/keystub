package swap

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
)

type swapCase struct {
	Name        string            `json:"name"`
	Service     string            `json:"service"`
	URL         string            `json:"url"` // path and query; "/" when absent
	Request     map[string]string `json:"request"`
	RealKey     string            `json:"realKey"`
	Token       string            `json:"token"`
	Upstream    map[string]string `json:"upstream"`
	UpstreamURL string            `json:"upstreamUrl"` // unchecked when absent
	Refused     bool              `json:"refused"`
}

type scrubCase struct {
	Name     string `json:"name"`
	Service  string `json:"service"`
	RealKey  string `json:"realKey"`
	Token    string `json:"token"`
	Response struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"response"`
	Client struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"client"`
}

// TestConformance runs the cases every Keystub data plane must pass.
func TestConformance(t *testing.T) {
	b, err := os.ReadFile("../../conformance/swap.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AuthHeaders []string    `json:"authHeaders"`
		Cases       []swapCase  `json:"cases"`
		Scrub       []scrubCase `json:"scrub"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	if !slices.Equal(f.AuthHeaders, AuthHeaders) {
		t.Fatalf("authHeaders in swap.json %v, in Go %v", f.AuthHeaders, AuthHeaders)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			svc, ok := catalog.Preset(c.Service)
			if !ok {
				t.Fatalf("no service %q in the catalog", c.Service)
			}
			h := http.Header{}
			for k, v := range c.Request {
				h.Set(k, v)
			}
			raw := c.URL
			if raw == "" {
				raw = "/"
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			stray := append(Stray(h, svc.Header), URLStray(u, svc)...)
			if (len(stray) > 0) != c.Refused {
				t.Fatalf("Stray, URLStray = %v, refused = %v", stray, c.Refused)
			}
			if c.Refused {
				return
			}
			got := Find(h, svc.Header)
			if got == "" {
				got = FindURL(u, svc)
			}
			if got != c.Token {
				t.Fatalf("Find, FindURL = %q, want %q", got, c.Token)
			}
			Request(h, u, c.RealKey, svc)
			for k, want := range c.Upstream {
				if got := h.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			if c.UpstreamURL != "" && u.RequestURI() != c.UpstreamURL {
				t.Errorf("URL = %q, want %q", u.RequestURI(), c.UpstreamURL)
			}
			if left := Find(h, svc.Header); left != "" || len(Stray(h, svc.Header)) > 0 || InURL(u) != "" {
				t.Errorf("a proxy token is still in the request: %q", left)
			}
		})
	}
}

// TestScrubConformance feeds each case's body whole, a byte at a time and
// in odd chunks.
func TestScrubConformance(t *testing.T) {
	b, err := os.ReadFile("../../conformance/swap.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Scrub []scrubCase `json:"scrub"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Scrub) == 0 {
		t.Fatal("no scrub cases")
	}
	for _, c := range f.Scrub {
		for _, chunk := range []int{0, 1, 3, 7} {
			t.Run(fmt.Sprintf("%s/chunk %d", c.Name, chunk), func(t *testing.T) {
				svc, ok := catalog.Preset(c.Service)
				if !ok || !KeyInURL(svc) {
					t.Fatalf("%q isn't a catalog service with its key in the URL", c.Service)
				}
				resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(chunked(c.Response.Body, chunk))}
				for k, v := range c.Response.Headers {
					resp.Header.Set(k, v)
				}
				NewScrubber(c.RealKey, c.Token).Response(resp)
				got, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != c.Client.Body {
					t.Errorf("body = %q, want %q", got, c.Client.Body)
				}
				for k, want := range c.Client.Headers {
					if got := resp.Header.Get(k); got != want {
						t.Errorf("%s = %q, want %q", k, got, want)
					}
				}
			})
		}
	}
}

// chunked reads s n bytes at a time (all at once for 0).
func chunked(s string, n int) io.Reader {
	if n == 0 {
		return strings.NewReader(s)
	}
	return &slowReader{s: s, n: n}
}

type slowReader struct {
	s string
	n int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.s == "" {
		return 0, io.EOF
	}
	k := copy(p[:min(len(p), r.n)], r.s)
	r.s = r.s[k:]
	return k, nil
}

func TestScrubGzipAndUnknownEncodings(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write([]byte("next=?k=real-key"))
	_ = zw.Close()
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(&zb)}
	NewScrubber("real-key", "sk-stub-0a").Response(resp)
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != "next=?k=sk-stub-0a" || resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("gzip: %q, %v, %q", got, err, resp.Header.Get("Content-Encoding"))
	}
	resp = &http.Response{Header: http.Header{"Content-Encoding": {"br"}}, Body: io.NopCloser(strings.NewReader("anything"))}
	NewScrubber("real-key", "sk-stub-0a").Response(resp)
	if got, err := io.ReadAll(resp.Body); err == nil || len(got) != 0 {
		t.Fatalf("br: passed on %q, %v", got, err)
	}
}

func TestRedactPath(t *testing.T) {
	if got := RedactPath("/botsk-stub-0a1b/getMe/skstub99"); got != "/botsk-stub-…/getMe/skstub…" {
		t.Fatal(got)
	}
}

func TestTokenPicksTheEarliest(t *testing.T) {
	if got := token("skstubaa then sk-stub-bb"); got != "skstubaa" {
		t.Fatalf("got %q", got)
	}
	if got := token("sk-stub- nothing, then sk-stub-cc"); got != "sk-stub-cc" {
		t.Fatalf("got %q", got)
	}
}

func TestRealKeyThatLooksLikeAToken(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer sk-stub-aa"}}
	Apply(h, "sk-stub-bb", "Authorization", "Bearer {key}")
	if got := h.Get("Authorization"); got != "Bearer sk-stub-bb" {
		t.Fatalf("got %q", got)
	}
}

func TestIn(t *testing.T) {
	tok := core.TokenPrefix + "0123456789abcdef0123456789abcdef0123"
	for in, want := range map[string]string{
		"Bearer " + tok:        tok,
		tok:                    tok,
		"token " + tok + " x":  tok,
		"Bearer sk-live-other": "",
	} {
		if got := In(in); got != want {
			t.Errorf("In(%q) = %q", in, got)
		}
	}
}
