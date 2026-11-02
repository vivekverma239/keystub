package usage

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

type usageCase struct {
	Name    string `json:"name"`
	Service string `json:"service"`
	Time    string `json:"time"`
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"response"`
	Expect struct {
		Operation  string      `json:"operation"`
		Model      string      `json:"model"`
		Outcome    string      `json:"outcome"`
		Usage      *core.Usage `json:"usage"`
		CostMicros *int64      `json:"costMicros"`
		Quota      *core.Quota `json:"quota"`
	} `json:"expect"`
}

// chunked hands out a body n bytes per Read, as a network would.
type chunked struct {
	b []byte
	n int
}

func (c *chunked) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	k := min(c.n, len(p), len(c.b))
	copy(p, c.b[:k])
	c.b = c.b[k:]
	return k, nil
}

func (c *chunked) Close() error { return nil }

func runCase(t *testing.T, c usageCase, chunk int, gz bool, read bool) core.Entry {
	t.Helper()
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	if c.Time != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, c.Time); err != nil {
			t.Fatal(err)
		}
	}
	m := Start(c.Service, c.Request.Method, c.Request.Path, at)
	if c.Request.Body != "" {
		rb := m.Request(io.NopCloser(&chunked{b: []byte(c.Request.Body), n: chunk}), http.Header{"Content-Type": {"application/json"}})
		if _, err := io.Copy(io.Discard, rb); err != nil {
			t.Fatal(err)
		}
	}
	resp := &http.Response{StatusCode: c.Response.Status, Header: http.Header{}}
	for k, v := range c.Response.Headers {
		resp.Header.Set(k, v)
	}
	body := []byte(c.Response.Body)
	if gz {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		body = buf.Bytes()
		resp.Header.Set("Content-Encoding", "gzip")
	}
	resp.Body = &chunked{b: body, n: chunk}
	m.Response(resp)
	if read {
		got, err := io.ReadAll(resp.Body)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("the body changed on its way through: %v", err)
		}
	}
	e := core.Entry{Service: c.Service, Status: c.Response.Status}
	m.Finish(&e)
	if e.Outcome == "" {
		e.Outcome = Outcome(c.Service, c.Response.Status, "")
	}
	_ = resp.Body.Close()
	return e
}

// TestConformance runs conformance/usage.json, the cases every Keystub data
// plane must read the same: each one whole, a byte at a time and in odd
// chunks, plain and gzipped.
func TestConformance(t *testing.T) {
	b, err := os.ReadFile("../../conformance/usage.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []usageCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		for _, chunk := range []int{1 << 20, 1, 7} {
			for _, gz := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/gzip=%v", c.Name, chunk, gz), func(t *testing.T) {
					if For(c.Service) == nil {
						t.Fatalf("%s has no usage metadata", c.Service)
					}
					e := runCase(t, c, chunk, gz, true)
					x := c.Expect
					if e.Operation != x.Operation || e.Model != x.Model || e.Outcome != x.Outcome {
						t.Fatalf("operation/model/outcome = %q/%q/%q, want %q/%q/%q", e.Operation, e.Model, e.Outcome, x.Operation, x.Model, x.Outcome)
					}
					if !reflect.DeepEqual(e.Usage, x.Usage) {
						t.Fatalf("usage = %+v, want %+v", e.Usage, x.Usage)
					}
					if !reflect.DeepEqual(e.CostMicros, x.CostMicros) {
						t.Fatalf("cost = %v, want %v", ptr(e.CostMicros), ptr(x.CostMicros))
					}
					if !reflect.DeepEqual(e.Quota, x.Quota) {
						t.Fatalf("quota = %+v, want %+v", e.Quota, x.Quota)
					}
				})
			}
		}
	}
}

func ptr(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// A response that is never read (the client went away) still finishes,
// gzipped or not, without waiting for the rest of the body.
func TestFinishWithoutReading(t *testing.T) {
	b, _ := os.ReadFile("../../conformance/usage.json")
	var f struct {
		Cases []usageCase `json:"cases"`
	}
	_ = json.Unmarshal(b, &f)
	for _, gz := range []bool{false, true} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			e := runCase(t, f.Cases[0], 3, gz, false)
			if e.Usage != nil {
				t.Errorf("gzip=%v: usage from an unread body: %+v", gz, e.Usage)
			}
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("gzip=%v: Finish hung on an unread body", gz)
		}
	}
}
