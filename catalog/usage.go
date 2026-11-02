package catalog

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

// Usage is a service's usage metadata: how to read, from a response as it
// streams past, which operation a request was, which model served it, what
// it used and how the service answered. Every Keystub data plane reads the
// same metadata, pinned down by conformance/usage.json.
//
// A term names where a number or string is read from. It is one or more
// alternatives separated by "|"; the term's value is the first alternative,
// in the order written, that was seen, and each alternative keeps the last
// value seen. An alternative is
//
//	usage.prompt_tokens     a dotted path into the response body's JSON, or
//	                        into each server-sent event's data (arrays are
//	                        transparent: a path matches inside any element)
//	request:model           the same, in the request body
//	header:x-usage          a response header
//	path:model              a {model} placeholder in the operation's path
//
// Token fields (Input, Cached, CacheWrite, Output, Units) are lists of
// terms that are added up, for services that count, say, cache reads apart
// from input.
type Usage struct {
	Operations []Operation `json:"operations,omitempty"`
	Model      string      `json:"model,omitempty"`
	// Input counts every input token, cached tokens and cache writes
	// included; Cached and CacheWrite are those parts. Output includes
	// reasoning tokens.
	Input      []string `json:"input,omitempty"`
	Cached     []string `json:"cached,omitempty"`
	CacheWrite []string `json:"cacheWrite,omitempty"`
	Output     []string `json:"output,omitempty"`
	// Units count something other than tokens (searches, characters);
	// UnitName says what, for display.
	Units    []string `json:"units,omitempty"`
	UnitName string   `json:"unitName,omitempty"`
	// Cost is a term holding the request's cost in US dollars as the
	// service reported it. When it is seen, it wins over pricing.json.
	Cost string `json:"cost,omitempty"`
	// CostPerUSD is how many of Cost's units make a dollar, for services
	// that report cost in smaller units (xAI's ticks: 10¹⁰). Default 1.
	CostPerUSD float64 `json:"costPerUsd,omitempty"`
	// Status maps upstream statuses to outcomes where the default (401 key
	// rejected, 429 rate limited, 5xx upstream error, other 4xx client
	// error) is wrong for this service. Keys are "403" or "5xx"-style.
	Status map[string]string `json:"status,omitempty"`
	// Quota names the response headers with the service's remaining
	// requests and tokens.
	Quota struct {
		Requests string `json:"requests,omitempty"`
		Tokens   string `json:"tokens,omitempty"`
	} `json:"quota,omitzero"`
}

// Operation names requests by method and path. Path is matched whole;
// "{name}" matches within one segment (up to "/" or ":"), "*" matches one
// segment and a trailing "/**" anything after.
type Operation struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

var (
	opName      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	pathAlt     = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$`)
	headerName  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	opPathChars = regexp.MustCompile(`^/[A-Za-z0-9_.:{}*/-]*$`)
	placeholder = regexp.MustCompile(`\{([a-z]+)\}`)
	statusKey   = regexp.MustCompile(`^[1-5]([0-9]{2}|xx)$`)
)

// Outcomes is every outcome a status may map to.
var Outcomes = []string{core.OutcomeOK, core.OutcomeClientError, core.OutcomeKeyRejected,
	core.OutcomeRateLimited, core.OutcomeUpstreamError}

// MaxPathDepth is how deep a JSON path may go; deeper values are never read.
const MaxPathDepth = 8

func (u *Usage) validate() error {
	seen := map[string]bool{}
	for _, o := range u.Operations {
		if !opName.MatchString(o.Name) {
			return fmt.Errorf("operation name %q: lowercase letters, digits, - and _", o.Name)
		}
		if o.Method != strings.ToUpper(o.Method) || o.Method == "" {
			return fmt.Errorf("operation %s: method %q must be upper case", o.Name, o.Method)
		}
		if !opPathChars.MatchString(o.Path) {
			return fmt.Errorf("operation %s: path %q must start with / and use only path characters", o.Name, o.Path)
		}
		if i := strings.Index(o.Path, "**"); i >= 0 && (i != len(o.Path)-2 || !strings.HasSuffix(o.Path, "/**")) {
			return fmt.Errorf("operation %s: ** only as the last segment", o.Name)
		}
		for _, m := range placeholder.FindAllStringSubmatch(o.Path, -1) {
			if m[1] != "model" {
				return fmt.Errorf("operation %s: only {model} is a placeholder", o.Name)
			}
		}
		if strings.Count(o.Path, "{") != len(placeholder.FindAllString(o.Path, -1)) {
			return fmt.Errorf("operation %s: bad placeholder in %q", o.Name, o.Path)
		}
		key := o.Method + " " + o.Path
		if seen[key] {
			return fmt.Errorf("operation %s repeats %s", o.Name, key)
		}
		seen[key] = true
	}
	terms := map[string][]string{"input": u.Input, "cached": u.Cached, "cacheWrite": u.CacheWrite, "output": u.Output, "units": u.Units}
	for field, ts := range terms {
		for _, t := range ts {
			if err := ValidateTerm(t); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	for field, t := range map[string]string{"model": u.Model, "cost": u.Cost} {
		if t == "" {
			continue
		}
		if err := ValidateTerm(t); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	if u.CostPerUSD < 0 || u.CostPerUSD > 0 && u.Cost == "" {
		return errors.New("costPerUsd needs a cost term and must be positive")
	}
	if len(u.Units) > 0 && u.UnitName == "" {
		return errors.New("units need a unitName")
	}
	for k, v := range u.Status {
		if !statusKey.MatchString(k) {
			return fmt.Errorf("status %q: use a status like 403 or a class like 5xx", k)
		}
		ok := false
		for _, o := range Outcomes {
			ok = ok || o == v
		}
		if !ok {
			return fmt.Errorf("status %s: unknown outcome %q", k, v)
		}
	}
	for _, h := range []string{u.Quota.Requests, u.Quota.Tokens} {
		if h != "" && !headerName.MatchString(h) {
			return fmt.Errorf("quota header %q", h)
		}
	}
	return nil
}

// Source is where a term's alternative is read from.
type Source int

const (
	FromBody    Source = iota // the response body
	FromRequest               // the request body
	FromHeader                // a response header
	FromPath                  // the operation path's {model}
)

// Alt is one alternative of a term.
type Alt struct {
	Source Source
	Name   string // a dotted path, a header name or "model"
}

// ParseTerm splits a term into its alternatives.
func ParseTerm(t string) ([]Alt, error) {
	var out []Alt
	for _, a := range strings.Split(t, "|") {
		alt := Alt{Source: FromBody, Name: a}
		if p, rest, ok := strings.Cut(a, ":"); ok {
			alt.Name = rest
			switch p {
			case "request":
				alt.Source = FromRequest
			case "header":
				alt.Source = FromHeader
			case "path":
				alt.Source = FromPath
			default:
				return nil, fmt.Errorf("term %q: unknown source %q", t, p)
			}
		}
		switch alt.Source {
		case FromHeader:
			if !headerName.MatchString(alt.Name) {
				return nil, fmt.Errorf("term %q: bad header %q", t, alt.Name)
			}
		case FromPath:
			if alt.Name != "model" {
				return nil, fmt.Errorf("term %q: only path:model", t)
			}
		default:
			if !pathAlt.MatchString(alt.Name) || strings.Count(alt.Name, ".") >= MaxPathDepth {
				return nil, fmt.Errorf("term %q: bad path %q", t, alt.Name)
			}
		}
		out = append(out, alt)
	}
	return out, nil
}

// ValidateTerm checks a term's syntax.
func ValidateTerm(t string) error {
	_, err := ParseTerm(t)
	return err
}

// StatusOutcome returns the outcome for an upstream status, using the
// service's own mapping where it has one.
func (u *Usage) StatusOutcome(status int) string {
	if u != nil && u.Status != nil {
		s := strconv.Itoa(status)
		if o, ok := u.Status[s]; ok {
			return o
		}
		if len(s) == 3 {
			if o, ok := u.Status[s[:1]+"xx"]; ok {
				return o
			}
		}
	}
	return DefaultOutcome(status)
}

// DefaultOutcome is the outcome of an upstream status for a service with
// no mapping of its own.
func DefaultOutcome(status int) string {
	switch {
	case status == 401:
		return core.OutcomeKeyRejected
	case status == 429:
		return core.OutcomeRateLimited
	case status >= 500:
		return core.OutcomeUpstreamError
	case status >= 400:
		return core.OutcomeClientError
	default:
		return core.OutcomeOK
	}
}
