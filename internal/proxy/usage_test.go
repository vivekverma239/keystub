package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/ca"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/reqlog"
)

// secretText appears in every body these tests send; it must never reach
// the request log.
const secretText = "CONTENT-THAT-MUST-NOT-BE-LOGGED"

// openaiRig is a proxy whose "openai" service (catalog usage metadata
// included) lives on the test upstream.
func openaiRig(t *testing.T, handler http.HandlerFunc) (*rig, string) {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)
	s, dir := coretest.Engine(t, "")
	c, err := ca.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := reqlog.Open("", 50)
	if err := s.AddService(bg, core.Service{ID: "openai", Name: "OpenAI", Hosts: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, s, core.DefaultEnv, "openai", "sk-real"); err != nil {
		t.Fatal(err)
	}
	p := New(s, c, l)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	p.Upstream = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true, DisableCompression: true}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, _ := url.Parse(ps.URL)
	r := &rig{store: keys{s}, log: l, ca: c, proxyURL: pu, upstream: up}
	token, _, _ := r.store.CreateKey("usage", 0)
	return r, token
}

func noContent(t *testing.T, e core.Entry) {
	t.Helper()
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), secretText) || strings.Contains(string(b), "sk-real") {
		t.Fatalf("the log holds content: %s", b)
	}
}

func TestProxyMetersAGzippedStreamWithoutBufferingIt(t *testing.T) {
	release := make(chan struct{})
	var sawEncoding string
	r, token := openaiRig(t, func(w http.ResponseWriter, req *http.Request) {
		sawEncoding = req.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("x-ratelimit-remaining-requests", "7")
		zw := gzip.NewWriter(w)
		_, _ = io.WriteString(zw, `data: {"model":"gpt-6-sol","choices":[{"delta":{"content":"`+secretText+`"}}]}`+"\n\n")
		_ = zw.Flush()
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			return
		}
		_, _ = io.WriteString(zw, `data: {"model":"gpt-6-sol","choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":100}}`+"\n\ndata: [DONE]\n\n")
		_ = zw.Close()
	})
	req, _ := http.NewRequest("POST", r.upstream.URL+"/v1/chat/completions", strings.NewReader(`{"model":"gpt-6-sol","stream":true,"messages":[{"role":"user","content":"`+secretText+`"}]}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, br, zstd")
	resp, err := r.client(r.ca.Pool(), token).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("content-encoding %q", resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(zr)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, secretText) {
		t.Fatalf("first event %q, %v", line, err)
	}
	close(release) // the first event arrived before the rest was sent
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "[DONE]") {
		t.Fatalf("rest = %q", rest)
	}
	if sawEncoding != "gzip" {
		t.Fatalf("upstream Accept-Encoding %q, want only what the meter reads", sawEncoding)
	}
	e := r.waitLog(t, 1)[0]
	if e.Operation != "chat" || e.Model != "gpt-6-sol" || e.Outcome != core.OutcomeOK || e.Usage == nil ||
		e.Usage.InputTokens != 1000 || e.Usage.OutputTokens != 100 || e.CostMicros == nil || *e.CostMicros != 3000 ||
		e.Quota == nil || *e.Quota.RequestsLeft != 7 {
		t.Fatalf("entry = %+v usage %+v", e, e.Usage)
	}
	noContent(t, e)
}

func TestProxyOutcomes(t *testing.T) {
	r, token := openaiRig(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"Incorrect API key `+secretText+`"}}`)
	})
	resp, err := r.client(r.ca.Pool(), token).Post(r.upstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	e := r.waitLog(t, 1)[0]
	if e.Outcome != core.OutcomeKeyRejected || e.Note != "" || e.Usage != nil {
		t.Fatalf("upstream 401: %+v", e)
	}
	noContent(t, e)

	resp, err = r.client(r.ca.Pool(), "sk-stub-unknown").Post(r.upstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if e := r.waitLog(t, 2)[0]; e.Outcome != core.OutcomeRefused || e.Status != http.StatusUnauthorized {
		t.Fatalf("Keystub's own 401: %+v", e)
	}
}

func TestEdgeMetersUsageAndReadsTheModelFromTheRequest(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+secretText+`"}}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`)
	}))
	t.Cleanup(up.Close)
	e, _ := coretest.Engine(t, "")
	if err := e.AddService(bg, core.Service{ID: "openai", Name: "OpenAI", Hosts: []string{"api.openai.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, e, core.DefaultEnv, "openai", "sk-real"); err != nil {
		t.Fatal(err)
	}
	token, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "quick"})
	l, _ := reqlog.Open("", 50)
	ed := NewEdge(e, l)
	pool := x509.NewCertPool()
	pool.AddCert(up.Certificate())
	addr := up.Listener.Addr().String()
	ed.Upstream = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	srv := httptest.NewServer(ed)
	t.Cleanup(srv.Close)

	body := `{"messages":[{"role":"user","content":"` + secretText + `"}],"model":"gpt-6-luna"}`
	req, _ := http.NewRequest("POST", srv.URL+"/s/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(got, []byte(secretText)) {
		t.Fatalf("body %q", got)
	}
	// The entry is logged once the body is done, which may be just after
	// the client has read it.
	en := waitEntries(t, l, 1)[0]
	if en.Operation != "chat" || en.Model != "gpt-6-luna" || en.Usage == nil || en.Usage.InputTokens != 10 || en.CostMicros == nil || *en.CostMicros != 2 || en.Outcome != core.OutcomeOK {
		t.Fatalf("entry = %+v", en)
	}
	noContent(t, en)
}

func TestAgentLogsTheEdgesOwnAnswers(t *testing.T) {
	c, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, _ := reqlog.Open("", 10)
	eu, _ := url.Parse("https://edge.invalid")
	p := NewAgent(hostSet{{ID: "echo", Name: "Echo", Hosts: []string{"echo.example"}, Header: "Authorization"}}, eu, c, l)
	var status int
	var outcome string
	p.Upstream = roundTripFunc(func(*http.Request) (*http.Response, error) {
		h := http.Header{}
		if outcome != "" {
			h.Set(OutcomeHeader, outcome)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader("{}")), ContentLength: 2}, nil
	})
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	pu, _ := url.Parse(ps.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: c.Pool()}}}
	for i, tc := range []struct {
		status        int
		outcome, want string
	}{
		{429, core.OutcomeRefused, core.OutcomeRefused}, // a Keystub limit at the edge
		{429, "", core.OutcomeRateLimited},              // the service's own 429
		{502, core.OutcomeUnreachable, core.OutcomeUnreachable},
		{401, "ok", core.OutcomeKeyRejected}, // only known outcomes are taken
	} {
		status, outcome = tc.status, tc.outcome
		req, _ := http.NewRequest("GET", "https://echo.example/v1/x", nil)
		req.Header.Set("Authorization", "Bearer sk-stub-0123456789abcdef0123456789abcdef0123")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if e := waitEntries(t, l, i+1)[0]; e.Outcome != tc.want {
			t.Errorf("%d with %q: outcome %q, want %q", tc.status, tc.outcome, e.Outcome, tc.want)
		}
	}
}

func waitEntries(t *testing.T, l *reqlog.Log, n int) []core.Entry {
	t.Helper()
	for i := 0; i < 200; i++ {
		if es := l.Recent(n); len(es) == n {
			return es
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("log never reached %d entries", n)
	return nil
}

func TestEdgeLogsAClientThatHungUpAsCanceled(t *testing.T) {
	e, _ := coretest.Engine(t, "")
	if err := e.AddService(bg, core.Service{ID: "openai", Name: "OpenAI", Hosts: []string{"api.openai.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := coretest.SetSecret(bg, e, core.DefaultEnv, "openai", "sk-real"); err != nil {
		t.Fatal(err)
	}
	token, _, _ := e.CreateToken(bg, core.TokenSpec{EnvID: core.DefaultEnv, Name: "quick"})
	l, _ := reqlog.Open("", 10)
	ed := NewEdge(e, l)
	var upstreamHeader string
	ed.Upstream = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Hang") == "" {
			h := http.Header{OutcomeHeader: {"refused"}}
			return &http.Response{StatusCode: 200, Header: h, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	// A service can't pass for Keystub refusing.
	req := httptest.NewRequest("POST", "/s/openai/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	ed.ServeHTTP(w, req)
	upstreamHeader = w.Header().Get(OutcomeHeader)
	if upstreamHeader != "" {
		t.Fatalf("the service's %s header reached the client", OutcomeHeader)
	}
	// Keystub's own refusal is marked.
	req = httptest.NewRequest("POST", "/s/openai/v1/chat/completions", strings.NewReader(`{}`))
	w = httptest.NewRecorder()
	ed.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || w.Header().Get(OutcomeHeader) != core.OutcomeRefused {
		t.Fatalf("refusal %d %q", w.Code, w.Header().Get(OutcomeHeader))
	}

	ctx, cancel := context.WithCancel(context.Background())
	req = httptest.NewRequest("POST", "/s/openai/v1/chat/completions", strings.NewReader(`{}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Hang", "1")
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	ed.ServeHTTP(httptest.NewRecorder(), req)
	if en := l.Recent(1)[0]; en.Outcome != core.OutcomeCanceled || en.Note != "client went away" {
		t.Fatalf("entry = %+v", en)
	}
}

// failingBody sends some bytes and then fails, as a client that hangs up
// mid-upload would.
type failingBody struct{ sent bool }

func (b *failingBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, `{"model":"gpt`), nil
}

func TestProxyLogsAClientThatStopsSendingAsCanceled(t *testing.T) {
	r, token := openaiRig(t, func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
	})
	req, _ := http.NewRequest("POST", r.upstream.URL+"/v1/chat/completions", &failingBody{})
	req.ContentLength = 1000
	req.Header.Set("Content-Type", "application/json")
	if resp, err := r.client(r.ca.Pool(), token).Do(req); err == nil {
		resp.Body.Close()
	}
	e := r.waitLog(t, 1)[0]
	if e.Outcome != core.OutcomeCanceled || e.Status != 0 {
		t.Fatalf("entry = %+v", e)
	}
}
