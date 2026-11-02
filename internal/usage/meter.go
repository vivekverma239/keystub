// Package usage reads what a request used from its response as it streams
// past, by the catalog's usage metadata (catalog.Usage), and adds requests
// up into hourly metrics. It never holds a body: JSON and server-sent
// events are scanned byte by byte for a few paths, and only the numbers
// and the model name found there are kept.
package usage

import (
	"compress/gzip"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
)

// MaxScan is how many bytes of a body (after decompression) are scanned.
// Past it the response still streams; it just isn't read any more.
const MaxScan = 64 << 20

type alt struct {
	src    catalog.Source
	slot   int    // in the body's or the request's values
	header string // for FromHeader
}

type term []alt

type op struct {
	name, method string
	re           *regexp.Regexp
	under        *regexp.Regexp // paths below the operation's
	model        int            // submatch index of {model}, 0 for none
}

// Spec is a service's usage metadata, compiled.
type Spec struct {
	service                                  string
	u                                        *catalog.Usage
	ops                                      []op
	model, cost                              term
	input, cached, cacheWrite, output, units []term
	body, req                                map[string]int // path → slot
}

var (
	specsOnce sync.Once
	specs     map[string]*Spec
)

// For returns the built-in catalog's usage metadata for a service, or nil.
func For(serviceID string) *Spec {
	specsOnce.Do(func() {
		specs = map[string]*Spec{}
		for _, p := range catalog.Presets {
			if e, ok := catalog.Lookup(p.ID); ok && e.Usage != nil {
				s, err := Compile(p.ID, e.Usage)
				if err != nil {
					panic(err) // the catalog's own test checks every entry
				}
				specs[p.ID] = s
			}
		}
	})
	return specs[serviceID]
}

// Compile turns usage metadata into a Spec.
func Compile(service string, u *catalog.Usage) (*Spec, error) {
	s := &Spec{service: service, u: u, body: map[string]int{}, req: map[string]int{}}
	for _, o := range u.Operations {
		re, under, idx := opRegexp(o.Path)
		s.ops = append(s.ops, op{name: o.Name, method: o.Method, re: re, under: under, model: idx})
	}
	parse := func(t string) (term, error) {
		if t == "" {
			return nil, nil
		}
		alts, err := catalog.ParseTerm(t)
		if err != nil {
			return nil, err
		}
		var out term
		for _, a := range alts {
			x := alt{src: a.Source, slot: -1}
			switch a.Source {
			case catalog.FromBody:
				x.slot = slotFor(s.body, a.Name)
			case catalog.FromRequest:
				x.slot = slotFor(s.req, a.Name)
			case catalog.FromHeader:
				x.header = a.Name
			}
			out = append(out, x)
		}
		return out, nil
	}
	var err error
	if s.model, err = parse(u.Model); err != nil {
		return nil, err
	}
	if s.cost, err = parse(u.Cost); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		dst *[]term
		src []string
	}{{&s.input, u.Input}, {&s.cached, u.Cached}, {&s.cacheWrite, u.CacheWrite}, {&s.output, u.Output}, {&s.units, u.Units}} {
		for _, t := range f.src {
			tt, err := parse(t)
			if err != nil {
				return nil, err
			}
			*f.dst = append(*f.dst, tt)
		}
	}
	return s, nil
}

func slotFor(m map[string]int, path string) int {
	if i, ok := m[path]; ok {
		return i
	}
	m[path] = len(m)
	return m[path]
}

// opRegexp compiles an operation path: {model} within a segment, * one
// segment, a trailing /** anything. under matches the paths below it.
func opRegexp(p string) (re, under *regexp.Regexp, model int) {
	var b strings.Builder
	b.WriteString("^")
	idx, groups := 0, 0
	rest := strings.TrimSuffix(p, "/**")
	for i := 0; i < len(rest); {
		switch {
		case strings.HasPrefix(rest[i:], "{model}"):
			groups++
			idx = groups
			b.WriteString(`([^/:]+)`)
			i += len("{model}")
		case rest[i] == '*':
			b.WriteString(`[^/]+`)
			i++
		default:
			b.WriteString(regexp.QuoteMeta(rest[i : i+1]))
			i++
		}
	}
	under = regexp.MustCompile(b.String() + "/[^/]") // a segment, not just a trailing slash
	if strings.HasSuffix(p, "/**") {
		b.WriteString(`(?:/.*)?`)
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()), under, idx
}

// StatusPage is the service's status page from the catalog, or "".
func StatusPage(serviceID string) string {
	e, _ := catalog.Lookup(serviceID)
	return e.StatusPage
}

// Outcome is a finished request's outcome. A note means Keystub answered
// itself; otherwise the upstream status decides, by the service's mapping.
func Outcome(serviceID string, status int, note string) string {
	if note != "" {
		return core.OutcomeRefused
	}
	if status == 0 {
		return core.OutcomeUnreachable
	}
	var u *catalog.Usage
	if s := For(serviceID); s != nil {
		u = s.u
	}
	return u.StatusOutcome(status)
}

// Narrow keeps only the encodings a meter reads (gzip, identity) in a
// request's Accept-Encoding, so the response comes back plain or gzipped. Parts that
// refuse an encoding (q=0) go too, so what's left never refuses them all.
// It does nothing for a service with no usage metadata.
func Narrow(serviceID string, h http.Header) {
	if For(serviceID) == nil || len(h.Values("Accept-Encoding")) == 0 {
		return
	}
	var keep []string
	for _, v := range h.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(part, ";")
			if refuses(params) {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(coding)) {
			case "gzip", "x-gzip", "identity":
				keep = append(keep, strings.TrimSpace(part))
			}
		}
	}
	if len(keep) == 0 {
		h.Del("Accept-Encoding")
		return
	}
	h.Set("Accept-Encoding", strings.Join(keep, ", "))
}

// refuses reports whether an Accept-Encoding part's parameters set q=0.
func refuses(params string) bool {
	for _, p := range strings.Split(params, ";") {
		k, v, _ := strings.Cut(p, "=")
		if strings.EqualFold(strings.TrimSpace(k), "q") {
			if q, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && q == 0 {
				return true
			}
		}
	}
	return false
}

// Meter reads one request's usage. A nil *Meter is valid and reads
// nothing, so callers needn't check whether a service has metadata.
type Meter struct {
	spec      *Spec
	at        time.Time
	operation string
	pathModel string
	metered   bool // a matched operation, or a request that isn't a GET

	reqMu   sync.Mutex // the request body is read on the transport's goroutine
	reqVals []value
	reqScan *jsonScanner

	bodyVals []value
	headers  map[string]string // only the headers the metadata names
	body     *meteredBody
	scan     *jsonScanner // the response body's, once it is scanned
	status   int          // the upstream status, 0 before a response
}

// Start begins metering a request to a service: it names the operation
// from the method and path (no query string).
func Start(serviceID, method, path string, at time.Time) *Meter {
	s := For(serviceID)
	if s == nil {
		return nil
	}
	// A GET nobody listed (a stored response, a job's status) returns usage
	// already counted; any other unlisted request (an image, a
	// transcription) is metered with no operation name.
	m := &Meter{spec: s, at: at, bodyVals: make([]value, len(s.body)), metered: method != http.MethodGet && method != http.MethodHead}
	path = removeDotSegments(path)
	for _, o := range s.ops {
		if o.method != method {
			continue
		}
		if sm := o.re.FindStringSubmatch(path); sm != nil {
			m.operation, m.metered = o.name, true
			if o.model > 0 {
				m.pathModel = sm[o.model]
			}
			break
		}
	}
	// Below a listed operation (POST /v1/chat/completions/{id} updates a
	// stored completion, /v1/responses/{id}/cancel) the body repeats the
	// usage of work already counted.
	for i := 0; m.operation == "" && m.metered && i < len(s.ops); i++ {
		if s.ops[i].under.MatchString(path) {
			m.metered = false
		}
	}
	return m
}

// Operation is the request's operation name, "" if none matched.
func (m *Meter) Operation() string {
	if m == nil {
		return ""
	}
	return m.operation
}

// Request scans a JSON request body as it is sent, for metadata that reads
// the model from the request. It returns the body to send instead.
func (m *Meter) Request(body io.ReadCloser, h http.Header) io.ReadCloser {
	if m == nil || len(m.spec.req) == 0 || body == nil || body == http.NoBody ||
		!isJSON(h.Get("Content-Type")) || h.Get("Content-Encoding") != "" {
		return body
	}
	m.reqVals = make([]value, len(m.spec.req))
	m.reqScan = newJSONScanner(m.spec.req, m.reqVals, MaxScan)
	return &reqBody{ReadCloser: body, m: m}
}

type reqBody struct {
	io.ReadCloser
	m *Meter
}

func (b *reqBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.m.reqMu.Lock()
		b.m.reqScan.feed(p[:n])
		b.m.reqMu.Unlock()
	}
	return n, err
}

// Response reads the headers the metadata names and, for a successful
// JSON or event-stream response, wraps the body so it is scanned as the
// caller reads it.
func (m *Meter) Response(resp *http.Response) {
	if m == nil || resp == nil {
		return
	}
	m.status = resp.StatusCode
	for _, name := range m.headerNames() {
		// The first value, up to any comma: the edge's port sees one header
		// joined with ", ", so both read the same thing.
		v, _, _ := strings.Cut(resp.Header.Get(name), ",")
		if v = strings.Trim(v, " \t"); v != "" { // HTTP whitespace only, as the edge trims it
			if m.headers == nil {
				m.headers = map[string]string{}
			}
			m.headers[strings.ToLower(name)] = v
		}
	}
	if !m.metered || resp.StatusCode < 200 || resp.StatusCode > 299 || len(m.spec.body) == 0 || resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	ct := resp.Header.Get("Content-Type")
	js := newJSONScanner(m.spec.body, m.bodyVals, MaxScan)
	var feed func([]byte)
	var finish func()
	switch {
	case isSSE(ct):
		p := &sseParser{js: js}
		feed, finish = p.feed, p.finish
	case isJSON(ct):
		feed, finish = js.feed, js.finish
	default:
		return
	}
	m.scan = js
	mb := &meteredBody{ReadCloser: resp.Body}
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
		mb.feed, mb.end = feed, finish
	case "gzip", "x-gzip":
		pr, pw := io.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer pr.CloseWithError(io.ErrClosedPipe) // a writer never blocks on us once we stop
			zr, err := gzip.NewReader(pr)
			if err != nil {
				return
			}
			buf := make([]byte, 32<<10)
			var n int64
			for n < MaxScan {
				k, err := zr.Read(buf)
				if k > 0 {
					feed(buf[:k])
					n += int64(k)
				}
				if err != nil {
					break
				}
			}
			finish()
		}()
		mb.feed = func(b []byte) { _, _ = pw.Write(b) }
		mb.end = func() { pw.Close(); <-done }
	default: // br, zstd, deflate: not read
		return
	}
	resp.Body = mb
	m.body = mb
}

func (m *Meter) headerNames() []string {
	var out []string
	q := m.spec.u.Quota
	for _, h := range []string{q.Requests, q.Tokens} {
		if h != "" {
			out = append(out, h)
		}
	}
	for _, ts := range [][]term{{m.spec.model, m.spec.cost}, m.spec.input, m.spec.cached, m.spec.cacheWrite, m.spec.output, m.spec.units} {
		for _, t := range ts {
			for _, a := range t {
				if a.src == catalog.FromHeader {
					out = append(out, a.header)
				}
			}
		}
	}
	return out
}

// meteredBody hands every byte read to a scanner on its way to the client.
type meteredBody struct {
	io.ReadCloser
	mu   sync.Mutex
	feed func([]byte)
	end  func()
	over bool
}

func (b *meteredBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.mu.Lock()
		if !b.over {
			b.feed(p[:n])
		}
		b.mu.Unlock()
	}
	if err != nil {
		b.stop()
	}
	return n, err
}

func (b *meteredBody) Close() error {
	b.stop()
	return b.ReadCloser.Close()
}

// stop ends scanning: at the end of the body, on Close, or when the
// request is logged, whichever is first.
func (b *meteredBody) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.over {
		b.over = true
		b.end()
	}
}

// get returns a term's value: its first alternative that was seen. The
// request's body and path are the client's words, so they count only once
// the service accepted the request (2xx): otherwise any made-up model name
// would become a metrics row of its own.
func (m *Meter) get(t term) (value, bool) {
	accepted := m.status >= 200 && m.status <= 299
	for _, a := range t {
		if (a.src == catalog.FromRequest || a.src == catalog.FromPath) && !accepted {
			continue
		}
		var v value
		switch a.src {
		case catalog.FromBody:
			v = m.bodyVals[a.slot]
		case catalog.FromRequest:
			if m.reqVals != nil {
				v = m.reqVals[a.slot]
			}
		case catalog.FromHeader:
			if s, ok := m.headers[strings.ToLower(a.header)]; ok {
				v = value{set: true, str: s}
				if f, ok := parseNumber(s); ok {
					v.isNum, v.num = true, f
				}
			}
		case catalog.FromPath:
			if m.pathModel != "" {
				v = value{set: true, str: m.pathModel}
			}
		}
		if v.set {
			return v, true
		}
	}
	return value{}, false
}

// sum adds up terms; seen reports whether any of them had a number.
func (m *Meter) sum(ts []term) (n int64, seen bool) {
	for _, t := range ts {
		if v, ok := m.get(t); ok && v.isNum && v.num >= 0 && v.num < 1e15 {
			n += int64(math.Round(v.num))
			seen = true
		}
	}
	return n, seen
}

// Finish stops scanning and writes what was read into the entry: model,
// usage, cost and quota. Call it once the response has been relayed (or
// abandoned); the operation is set too.
func (m *Meter) Finish(e *core.Entry) {
	if m == nil {
		return
	}
	if m.body != nil {
		m.body.stop()
	}
	m.reqMu.Lock()
	defer m.reqMu.Unlock()
	if m.reqScan != nil {
		m.reqScan.finish()
	}
	e.Operation = m.operation
	if m.scan != nil && m.scan.failed && e.Outcome == "" {
		// A 2xx whose body or stream reported an error (Anthropic's
		// overloaded_error mid-stream, say).
		e.Outcome = core.OutcomeUpstreamError
	}
	m.finishUsage(e)
	q := m.spec.u.Quota
	var quota core.Quota
	if v, ok := quotaHeader(m.headers, q.Requests); ok {
		quota.RequestsLeft = &v
	}
	if v, ok := quotaHeader(m.headers, q.Tokens); ok {
		quota.TokensLeft = &v
	}
	if quota.RequestsLeft != nil || quota.TokensLeft != nil {
		e.Quota = &quota
	}
}

// finishUsage writes the model, usage and cost of a metered request.
func (m *Meter) finishUsage(e *core.Entry) {
	if !m.metered {
		return
	}
	if v, ok := m.get(m.spec.model); ok && v.str != "" {
		e.Model = cleanModel(v.str)
	}
	var u core.Usage
	var any, s bool
	u.InputTokens, s = m.sum(m.spec.input)
	any = any || s
	u.CachedTokens, s = m.sum(m.spec.cached)
	any = any || s
	u.CacheWriteTokens, s = m.sum(m.spec.cacheWrite)
	any = any || s
	u.OutputTokens, s = m.sum(m.spec.output)
	any = any || s
	u.Units, s = m.sum(m.spec.units)
	any = any || s
	if any {
		e.Usage = &u
	}
	perUSD := m.spec.u.CostPerUSD
	if perUSD == 0 {
		perUSD = 1
	}
	if v, ok := m.get(m.spec.cost); ok && v.isNum && v.num >= 0 && v.num/perUSD < 1e6 {
		c := int64(math.Round(v.num / perUSD * 1e6))
		e.CostMicros = &c
	} else if any && e.Model != "" {
		// Units with no unit price would cost $0: left unpriced instead.
		if p, ok := catalog.Prices.Lookup(m.spec.service, e.Model, m.at); ok && (u.Units == 0 || p.Unit > 0) {
			c := p.CostMicros(m.at, u.InputTokens, u.CachedTokens, u.CacheWriteTokens, u.OutputTokens, u.Units)
			e.CostMicros = &c
		}
	}
}

// removeDotSegments resolves "." and ".." in a path, as the edge's URL
// parser does, so "/v1/x/../chat/completions" matches the same operation.
func removeDotSegments(p string) string {
	if !strings.Contains(p, ".") {
		return p
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch {
		case i == 0:
			out = append(out, s)
		case s == ".":
			if last {
				out = append(out, "")
			}
		case s == "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, s)
		}
	}
	return strings.Join(out, "/")
}

func quotaHeader(h map[string]string, name string) (int64, bool) {
	if name == "" {
		return 0, false
	}
	s, ok := h[strings.ToLower(name)]
	if !ok {
		return 0, false
	}
	// Plain digits, few enough that the edge's port reads them exactly.
	if len(s) == 0 || len(s) > 15 || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// cleanModel keeps a model name to printable ASCII, so a strange one can't
// mangle a page or a CSV.
func cleanModel(s string) string {
	s = strings.TrimPrefix(s, "models/") // Gemini's resource names
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 96; i++ {
		c := s[i]
		if c > ' ' && c < 0x7f && c != '"' && c != '\'' && c != '<' && c != '>' && c != ',' {
			b.WriteByte(c)
		}
	}
	return b.String()
}
