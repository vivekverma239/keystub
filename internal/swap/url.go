package swap

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

// A few services read their key from the URL: one query parameter
// (core.Service.Query, Mapbox's access_token) or a spot in the path
// (core.Service.Paths, Telegram's /bot{key}/). A token is swapped only
// there. Anywhere else in the URL it refuses the request, as a token in a
// stray header does: URLs are logged and echoed back far more than auth
// headers. And since a service may echo its URL (a next-page link, a
// redirect), the real key is scrubbed from the responses of these
// services (see Scrubber).

// URLStray returns where in u a proxy token sits outside the service's key
// spots: "query parameter <name>" or "path". A request with any is refused.
func URLStray(u *url.URL, svc core.Service) []string {
	var out []string
	for _, p := range queryParts(u.RawQuery) {
		if token(p.name) != "" || token(p.value) != "" && (svc.Query == "" || p.name != svc.Query) {
			out = append(out, "query parameter "+p.name)
		}
	}
	path := u.EscapedPath()
	for _, at := range tokenSpans(path) {
		if !keySpot(path, at, svc.Paths) {
			out = append(out, "path")
			break
		}
	}
	return out
}

// FindURL returns the first proxy token in the service's key spots: its
// query parameter, then its path.
func FindURL(u *url.URL, svc core.Service) string {
	for _, p := range queryParts(u.RawQuery) {
		if svc.Query != "" && p.name == svc.Query {
			if t := token(p.value); t != "" {
				return t
			}
		}
	}
	path := u.EscapedPath()
	for _, at := range tokenSpans(path) {
		if keySpot(path, at, svc.Paths) {
			return path[at[0]:at[1]]
		}
	}
	return ""
}

// InURL returns a proxy token anywhere in u, for a proxy that leaves the
// checks to the edge it forwards to.
func InURL(u *url.URL) string {
	if t := token(u.EscapedPath()); t != "" {
		return t
	}
	for _, p := range queryParts(u.RawQuery) {
		if t := token(p.name + "=" + p.value); t != "" {
			return t
		}
	}
	return ""
}

// Request puts realKey in place of every proxy token in the request's auth
// headers and the service's key spots in u. If none held a token, it
// writes the key where the service reads it: its query parameter if it
// has one, else header: format; a service that reads its key only from
// the path gets nothing written. It reports whether a token was found.
// Call Stray and URLStray first.
func Request(h http.Header, u *url.URL, realKey string, svc core.Service) bool {
	inHeaders := swapHeaders(h, realKey, svc.Header)
	inURL := applyURL(u, realKey, svc)
	switch {
	case inHeaders || inURL:
		return true
	case svc.Query != "":
		setQuery(u, svc.Query, realKey)
	case len(svc.Paths) == 0:
		h.Set(svc.Header, strings.ReplaceAll(svc.Format, "{key}", realKey))
	}
	return false
}

// KeyInURL reports whether a service's key may travel in the URL, so its
// responses need scrubbing.
func KeyInURL(svc core.Service) bool { return svc.Query != "" || len(svc.Paths) > 0 }

// RedactPath masks the proxy tokens in a path before it's logged, keeping
// the prefix: "/botsk-stub-…/getMe".
func RedactPath(path string) string {
	spans := tokenSpans(path)
	if len(spans) == 0 {
		return path
	}
	var b strings.Builder
	last := 0
	for _, at := range spans {
		t := path[at[0]:at[1]]
		prefix := core.TokenPrefix
		if strings.HasPrefix(t, core.CompactPrefix) {
			prefix = core.CompactPrefix
		}
		b.WriteString(path[last:at[0]])
		b.WriteString(prefix + "…")
		last = at[1]
	}
	b.WriteString(path[last:])
	return b.String()
}

func swapHeaders(h http.Header, realKey, svcHeader string) bool {
	found := false
	for _, name := range names(h) {
		if !auth(name, svcHeader) {
			continue
		}
		vs := h[name]
		for i, v := range vs {
			if nv, ok := replace(v, realKey); ok {
				vs[i], found = nv, true
			}
		}
	}
	return found
}

func applyURL(u *url.URL, realKey string, svc core.Service) bool {
	found := false
	if svc.Query != "" {
		parts := queryParts(u.RawQuery)
		for i, p := range parts {
			if p.name == svc.Query && token(p.value) != "" {
				parts[i].raw = p.rawName + "=" + url.QueryEscape(replaceAll(p.value, realKey))
				found = true
			}
		}
		if found {
			u.RawQuery = joinQuery(parts)
		}
	}
	path := u.EscapedPath()
	spans := tokenSpans(path)
	if len(spans) > 0 {
		var b strings.Builder
		last := 0
		for _, at := range spans {
			if !keySpot(path, at, svc.Paths) {
				continue
			}
			b.WriteString(path[last:at[0]])
			b.WriteString(url.PathEscape(realKey))
			last, found = at[1], true
		}
		if last > 0 {
			b.WriteString(path[last:])
			if p, err := url.PathUnescape(b.String()); err == nil {
				u.Path, u.RawPath = p, b.String()
			}
		}
	}
	return found
}

// setQuery replaces the parameter's values with realKey, or adds it.
func setQuery(u *url.URL, name, realKey string) {
	var kept []queryPart
	for _, p := range queryParts(u.RawQuery) {
		if p.name != name {
			kept = append(kept, p)
		}
	}
	kept = append(kept, queryPart{raw: url.QueryEscape(name) + "=" + url.QueryEscape(realKey)})
	u.RawQuery = joinQuery(kept)
}

type queryPart struct {
	raw, rawName, name, value string
}

// queryParts splits a raw query on "&", keeping each part as sent so a
// swap changes nothing else. Names and values are unescaped for matching;
// one that doesn't unescape is matched as written.
func queryParts(raw string) []queryPart {
	if raw == "" {
		return nil
	}
	var out []queryPart
	for _, s := range strings.Split(raw, "&") {
		rn, rv, _ := strings.Cut(s, "=")
		n, err := url.QueryUnescape(rn)
		if err != nil {
			n = rn
		}
		v, err := url.QueryUnescape(rv)
		if err != nil {
			v = rv
		}
		out = append(out, queryPart{raw: s, rawName: rn, name: n, value: v})
	}
	return out
}

func joinQuery(parts []queryPart) string {
	s := make([]string, len(parts))
	for i, p := range parts {
		s[i] = p.raw
	}
	return strings.Join(s, "&")
}

// tokenSpans returns where each proxy token is in s.
func tokenSpans(s string) [][2]int {
	var out [][2]int
	for from := 0; from < len(s); {
		t := token(s[from:])
		if t == "" {
			break
		}
		i := from + strings.Index(s[from:], t)
		out = append(out, [2]int{i, i + len(t)})
		from = i + len(t)
	}
	return out
}

// keySpot reports whether the token at span sits where one of the
// service's path templates puts the key: "/bot{key}/" matches
// "/bot<token>/getMe" and nothing else.
func keySpot(path string, span [2]int, templates []string) bool {
	for _, t := range templates {
		pre, post, _ := strings.Cut(t, "{key}")
		if path[:span[0]] == pre && strings.HasPrefix(path[span[1]:], post) {
			return true
		}
	}
	return false
}

// Scrubber puts the proxy token back in place of the real key in a
// response, for services whose key travels in the URL: a next-page link,
// a redirect or a file URL would otherwise hand the box the real key.
type Scrubber struct {
	forms [][]byte // the key as it may be written: plain, query- and path-escaped
	token []byte
	max   int
}

// NewScrubber returns a scrubber that writes token wherever realKey is.
func NewScrubber(realKey, token string) *Scrubber {
	s := &Scrubber{token: []byte(token)}
	seen := map[string]bool{}
	for _, f := range []string{realKey, url.QueryEscape(realKey), url.PathEscape(realKey)} {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		s.forms = append(s.forms, []byte(f))
		s.max = max(s.max, len(f))
	}
	return s
}

// Header scrubs every response header value.
func (s *Scrubber) Header(h http.Header) {
	for _, vs := range h {
		for i, v := range vs {
			vs[i] = string(s.all([]byte(v)))
		}
	}
}

// Response scrubs a response's headers and wraps its body. The body's
// length may change, so Content-Length goes. Ask for an uncompressed body
// (see Uncompressed); a gzipped one is decompressed here, and one in any
// other encoding is cut off rather than passed on unread.
func (s *Scrubber) Response(resp *http.Response) {
	s.Header(resp.Header)
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	body := resp.Body
	switch enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			body = readCloser{errReader{errEncoding}, body}
			break
		}
		body = readCloser{zr, body}
		resp.Header.Del("Content-Encoding")
	default:
		body = readCloser{errReader{errEncoding}, body}
	}
	resp.Body = &scrubBody{r: body, s: s}
}

var errEncoding = errors.New("keystub: the service sent a compressed body the real key can't be scrubbed from")

// Uncompressed asks the service for a body the scrubber can read. The
// transports here don't ask for compression themselves, so with no
// Accept-Encoding the service sends the body as is.
func Uncompressed(h http.Header) { h.Del("Accept-Encoding") }

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r readCloser) Close() error { return r.c.Close() }

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func (s *Scrubber) all(b []byte) []byte {
	out, rest := s.cut(b, true)
	return append(out, rest...)
}

// cut replaces every key form in b. With final unset it holds back the
// tail that could still be the start of a form, returned as rest.
func (s *Scrubber) cut(b []byte, final bool) (out, rest []byte) {
	for {
		at, n := -1, 0
		for _, f := range s.forms {
			if i := bytes.Index(b, f); i >= 0 && (at < 0 || i < at || i == at && len(f) > n) {
				at, n = i, len(f)
			}
		}
		if at < 0 {
			break
		}
		out = append(append(out, b[:at]...), s.token...)
		b = b[at+n:]
	}
	if final || s.max <= 1 {
		return append(out, b...), nil
	}
	keep := min(len(b), s.max-1)
	return append(out, b[:len(b)-keep]...), b[len(b)-keep:]
}

type scrubBody struct {
	r       io.ReadCloser
	s       *Scrubber
	pending []byte // scrubbed, not yet read
	tail    []byte // unscrubbed bytes that might start a key
	err     error  // the body's error (io.EOF at its end), returned once pending is read
	buf     [32 << 10]byte
}

func (b *scrubBody) Read(p []byte) (int, error) {
	for len(b.pending) == 0 {
		if b.err != nil {
			return 0, b.err
		}
		n, err := b.r.Read(b.buf[:])
		in := append(b.tail, b.buf[:n]...)
		if err != nil {
			b.pending, b.tail, b.err = b.s.all(in), nil, err
			continue
		}
		var rest []byte
		b.pending, rest = b.s.cut(in, false)
		b.tail = bytes.Clone(rest)
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *scrubBody) Close() error { return b.r.Close() }
