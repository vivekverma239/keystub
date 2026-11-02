package usage

import (
	"strings"
	"testing"
)

func scan(t *testing.T, targets []string, input string, chunk int, sse bool) map[string]value {
	t.Helper()
	m := map[string]int{}
	for i, p := range targets {
		m[p] = i
	}
	vals := make([]value, len(targets))
	js := newJSONScanner(m, vals, 0)
	feed, finish := js.feed, js.finish
	if sse {
		p := &sseParser{js: js}
		feed, finish = p.feed, p.finish
	}
	b := []byte(input)
	for len(b) > 0 {
		n := min(chunk, len(b))
		feed(b[:n])
		b = b[n:]
	}
	finish()
	out := map[string]value{}
	for i, p := range targets {
		if vals[i].set {
			out[p] = vals[i]
		}
	}
	return out
}

func TestJSONScannerPaths(t *testing.T) {
	in := `{"id":"x","model":"gpt-5","choices":[{"message":{"content":"he said \"usage\": {\"prompt_tokens\": 99}"}}],
	 "usage":{"prompt_tokens":12,"completion_tokens":3.0,"prompt_tokens_details":{"cached_tokens":4}},"deep":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}}`
	targets := []string{"model", "usage.prompt_tokens", "usage.completion_tokens", "usage.prompt_tokens_details.cached_tokens", "deep.a.b.c.d.e.f.g.h", "missing"}
	for _, chunk := range []int{1, 2, 7, 64, len(in)} {
		got := scan(t, targets, in, chunk, false)
		if got["model"].str != "gpt-5" || got["usage.prompt_tokens"].num != 12 || got["usage.completion_tokens"].num != 3 ||
			got["usage.prompt_tokens_details.cached_tokens"].num != 4 {
			t.Fatalf("chunk %d: %+v", chunk, got)
		}
		if _, ok := got["deep.a.b.c.d.e.f.g.h"]; ok {
			t.Fatalf("chunk %d: read below the depth cap", chunk)
		}
		if _, ok := got["missing"]; ok {
			t.Fatal("missing path set")
		}
	}
}

func TestJSONScannerRootArrayAndLastWins(t *testing.T) {
	// Gemini's streamGenerateContent without alt=sse streams a JSON array.
	in := `[{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":1}},
	{"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":9},"modelVersion":"gemini-x"}]`
	got := scan(t, []string{"usageMetadata.candidatesTokenCount", "modelVersion"}, in, 3, false)
	if got["usageMetadata.candidatesTokenCount"].num != 9 || got["modelVersion"].str != "gemini-x" {
		t.Fatalf("%+v", got)
	}
}

func TestJSONScannerCapsAndJunk(t *testing.T) {
	long := strings.Repeat("a", maxValue+1)
	got := scan(t, []string{"model", "n"}, `{"model":"`+long+`","n":7}`, 5, false)
	if _, ok := got["model"]; ok {
		t.Fatal("kept a value past the cap")
	}
	if got["n"].num != 7 {
		t.Fatalf("%+v", got)
	}
	// Escaped keys never match: a body can't spell a path in escapes.
	got = scan(t, []string{"model"}, `{"mod`+"\\"+`u0065l":"x"}`, 1, false)
	if len(got) != 0 {
		t.Fatalf("%+v", got)
	}
	// Not JSON at all: nothing, and no panic.
	for _, junk := range []string{"[DONE]", "}}}", `{"a":}`, `{"a" 1}`, "\x00\xff"} {
		if got := scan(t, []string{"a"}, junk, 1, false); len(got) != 0 {
			t.Fatalf("%q: %+v", junk, got)
		}
	}
	// A number at the very end of the input.
	if got := scan(t, []string{""}, `42`, 1, false); got[""].num != 42 {
		t.Fatalf("%+v", got)
	}
}

func TestJSONScannerLimit(t *testing.T) {
	m := map[string]int{"n": 0}
	vals := make([]value, 1)
	js := newJSONScanner(m, vals, 10)
	js.feed([]byte(`{"pad":"0123456789","n":5}`))
	js.finish()
	if vals[0].set {
		t.Fatal("read past the byte limit")
	}
}

func TestSSEParser(t *testing.T) {
	in := "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-x\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\r\n\r\n" +
		": keep-alive\n\n" +
		"event: content_block_delta\ndata: {\"delta\":{\"text\":\"usage\"}}\n\n" +
		"data: {\"usage\":\n" +
		"data:  {\"output_tokens\":15}}\n\n" +
		"data: [DONE]\n\n"
	targets := []string{"message.model", "message.usage.input_tokens", "usage.output_tokens", "message.usage.output_tokens"}
	for _, chunk := range []int{1, 3, 17, len(in)} {
		got := scan(t, targets, in, chunk, true)
		if got["message.model"].str != "claude-x" || got["message.usage.input_tokens"].num != 25 ||
			got["usage.output_tokens"].num != 15 || got["message.usage.output_tokens"].num != 1 {
			t.Fatalf("chunk %d: %+v", chunk, got)
		}
	}
	// No blank line after the last event.
	got := scan(t, []string{"n"}, "data: {\"n\":3}", 2, true)
	if got["n"].num != 3 {
		t.Fatalf("%+v", got)
	}
	// A long field name or a non-data field is skipped.
	got = scan(t, []string{"n"}, "datadatadata: {\"n\":3}\nid: {\"n\":4}\n\n", 1, true)
	if len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestJSONScannerStackStaysSmall(t *testing.T) {
	js := newJSONScanner(map[string]int{"n": 0}, make([]value, 1), 0)
	js.feed([]byte(strings.Repeat("[", 1<<20)))
	if len(js.stack) > maxStack || cap(js.stack) > 2*maxStack {
		t.Fatalf("stack grew to %d (cap %d)", len(js.stack), cap(js.stack))
	}
	// Nesting under the cap still reads.
	deep := strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100) + `{"n":3}`
	if got := scan(t, []string{"n"}, deep, 7, false); got["n"].num != 3 {
		t.Fatalf("after deep nesting: %+v", got)
	}
}

func TestACutOffNumberIsDropped(t *testing.T) {
	if got := scan(t, []string{"usage.output_tokens"}, `{"usage":{"output_tokens":12`, 5, false); len(got) != 0 {
		t.Fatalf("partial number kept: %+v", got)
	}
	if got := scan(t, []string{"usage.output_tokens"}, "data: {\"usage\":{\"output_tokens\":12\n\n", 5, true); len(got) != 0 {
		t.Fatalf("partial number in an event kept: %+v", got)
	}
	if got := scan(t, []string{""}, `42`, 1, false); got[""].num != 42 {
		t.Fatalf("root number lost: %+v", got)
	}
}
