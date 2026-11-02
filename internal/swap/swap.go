// Package swap finds a proxy token in a request's auth headers and puts the
// real key in its place. Every data plane uses these rules; the shared cases
// in conformance/swap.json pin them down.
//
// Only auth headers are swapped: Authorization and the service's own header
// (x-api-key for Anthropic, say). A service may store or echo any other
// header (an idempotency key, a request ID, a header it doesn't know), so a
// token there could hand the real key back to the box; such a request is
// refused instead (see Stray).
package swap

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

// AuthHeaders are the headers a proxy token is swapped in for every
// service, besides the service's own header. Kept to Authorization on
// purpose: a generic "X-Api-Key" is an ordinary, possibly stored, header to
// most services.
var AuthHeaders = []string{"Authorization"}

// auth reports whether name is an auth header for a service whose own
// header is svcHeader.
func auth(name, svcHeader string) bool {
	name = http.CanonicalHeaderKey(name)
	return name == http.CanonicalHeaderKey(svcHeader) || slices.Contains(AuthHeaders, name)
}

// Find returns the first proxy token in h's auth headers, exactly as written
// (either form), also inside Basic auth. Headers are searched in name
// order, so the result doesn't depend on map order.
func Find(h http.Header, svcHeader string) string {
	for _, name := range names(h) {
		if !auth(name, svcHeader) {
			continue
		}
		for _, v := range h[name] {
			if t := In(v); t != "" {
				return t
			}
		}
	}
	return ""
}

// Stray returns the headers outside the auth headers that hold a proxy
// token. A request with any is refused, so the real key never lands in a
// header the service might keep or send back.
func Stray(h http.Header, svcHeader string) []string {
	var out []string
	for _, name := range names(h) {
		if auth(name, svcHeader) {
			continue
		}
		for _, v := range h[name] {
			if In(v) != "" {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// Apply swaps every proxy token in the auth headers for realKey, keeping
// each value's shape ("Bearer …", "token …", Basic auth, a prefixed deploy
// key). If none held a token, it writes header: format instead. It reports
// whether a token was found. Call Stray first: Apply leaves other headers
// alone.
func Apply(h http.Header, realKey, header, format string) bool {
	found := false
	for _, name := range names(h) {
		if !auth(name, header) {
			continue
		}
		vs := h[name]
		for i, v := range vs {
			if nv, ok := replace(v, realKey); ok {
				vs[i], found = nv, true
			}
		}
	}
	if !found {
		h.Set(header, strings.ReplaceAll(format, "{key}", realKey))
	}
	return found
}

// In finds a proxy token in one header value, including inside Basic auth
// (git over HTTPS sends "Basic base64(x-access-token:sk-stub-…)").
func In(v string) string {
	if t := token(v); t != "" {
		return t
	}
	if dec, ok := basic(v); ok {
		return token(dec)
	}
	return ""
}

// replace swaps every token in one value, plain or inside Basic auth.
func replace(v, realKey string) (string, bool) {
	if token(v) != "" {
		return replaceAll(v, realKey), true
	}
	if dec, ok := basic(v); ok && token(dec) != "" {
		scheme, _, _ := strings.Cut(v, " ")
		return scheme + " " + base64.StdEncoding.EncodeToString([]byte(replaceAll(dec, realKey))), true
	}
	return v, false
}

// replaceAll swaps each token in v in one pass over v, so a real key that
// happens to look like a token is never swapped again.
func replaceAll(v, realKey string) string {
	var b strings.Builder
	for {
		t := token(v)
		if t == "" {
			b.WriteString(v)
			return b.String()
		}
		i := strings.Index(v, t)
		b.WriteString(v[:i])
		b.WriteString(realKey)
		v = v[i+len(t):]
	}
}

func basic(v string) (string, bool) {
	scheme, enc, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// token pulls the first proxy token out of s, in either form.
func token(s string) string {
	best, at := "", -1
	for _, prefix := range []string{core.TokenPrefix, core.CompactPrefix} {
		for from := 0; ; {
			i := strings.Index(s[from:], prefix)
			if i < 0 {
				break
			}
			i += from
			j := i + len(prefix)
			for j < len(s) && isHex(s[j]) {
				j++
			}
			if j > i+len(prefix) {
				if at < 0 || i < at {
					best, at = s[i:j], i
				}
				break
			}
			from = i + len(prefix)
		}
	}
	return best
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

func names(h http.Header) []string {
	out := make([]string, 0, len(h))
	for k := range h {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
