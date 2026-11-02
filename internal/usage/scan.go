package usage

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/vivekverma239/keystub/catalog"
)

// value is the last value seen for one alternative of a term.
type value struct {
	set   bool
	isNum bool
	num   float64
	str   string
}

// Caps on what the scanners hold: a key or a captured value longer than
// these is dropped, never grown. Nothing else is kept.
const (
	maxKey   = 64
	maxValue = 128
)

// noPath marks a value whose path can't match any target: below
// MaxPathDepth, or under a key too long or escaped.
const noPath = "\x00"

type jstate uint8

const (
	jValue      jstate = iota // a value must come next
	jArrayFirst               // after "[": a value or "]"
	jObjFirst                 // after "{": a key or "}"
	jObjKey                   // after "," in an object: a key
	jColon                    // after a key
	jAfter                    // after a value in a container: "," or a close
	jString                   // inside a string
	jScalar                   // inside a number or literal
	jDone                     // the root value ended
	jFail                     // not JSON, or past the byte cap: ignore the rest
)

type frame struct {
	array bool
	depth int    // components in path: "" is 0, "usage.x" is 2
	path  string // an array's path, which its elements share
	child string // an object's current key's path
}

// jsonScanner reads values at a few dotted paths out of JSON fed to it in
// pieces of any size. It keeps a stack of open containers and the one key
// or value it is reading, so its memory doesn't grow with the input.
type jsonScanner struct {
	targets map[string]int // path → slot in vals
	vals    []value

	st       jstate
	stack    []frame
	isKey    bool
	esc      bool
	uni      int // \u hex digits still to come
	buf      []byte
	over     bool // buf passed its cap, or held an escape we don't decode
	slot     int  // where the current value goes, -1 for nowhere
	n, limit int64
	failed   bool // a root object had an "error" object: the service failed
}

func newJSONScanner(targets map[string]int, vals []value, limit int64) *jsonScanner {
	return &jsonScanner{targets: targets, vals: vals, slot: -1, limit: limit, buf: make([]byte, 0, maxValue)}
}

// reset starts a new root value, keeping the values seen so far: each
// server-sent event's data is its own JSON document.
func (s *jsonScanner) reset() {
	s.st, s.stack, s.slot = jValue, s.stack[:0], -1
}

// valuePath is the path of a value starting now.
func (s *jsonScanner) valuePath() (string, int) {
	if len(s.stack) == 0 {
		return "", 0
	}
	f := &s.stack[len(s.stack)-1]
	if f.array {
		return f.path, f.depth
	}
	return f.child, f.depth + 1
}

func (s *jsonScanner) feed(b []byte) {
	if s.st == jFail {
		return
	}
	if s.limit > 0 {
		if s.n >= s.limit {
			s.st = jFail
			return
		}
		if rem := s.limit - s.n; int64(len(b)) > rem {
			b = b[:rem]
		}
	}
	s.n += int64(len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch s.st {
		case jString:
			// Skip plain runs quickly; strings are most of an LLM response.
			if !s.esc && s.uni == 0 {
				j := i
				for j < len(b) && b[j] != '"' && b[j] != '\\' {
					j++
				}
				s.add(b[i:j])
				i = j
				if i == len(b) {
					return
				}
				c = b[i]
			}
			s.stringByte(c)
		case jScalar:
			if c == ',' || c == '}' || c == ']' || isSpace(c) {
				s.endScalar()
				i-- // the delimiter belongs to the container
				continue
			}
			s.add([]byte{c})
		case jValue, jArrayFirst:
			if isSpace(c) {
				continue
			}
			if c == ']' && s.st == jArrayFirst {
				s.closeContainer(true)
				continue
			}
			s.startValue(c)
		case jObjFirst, jObjKey:
			switch {
			case isSpace(c):
			case c == '}' && s.st == jObjFirst:
				s.closeContainer(false)
			case c == '"':
				s.isKey, s.esc, s.uni, s.buf, s.over = true, false, 0, s.buf[:0], false
				top := s.stack[len(s.stack)-1]
				s.over = top.path == noPath || top.depth+1 > catalog.MaxPathDepth
				s.st = jString
			default:
				s.st = jFail
				return
			}
		case jColon:
			switch {
			case isSpace(c):
			case c == ':':
				s.st = jValue
			default:
				s.st = jFail
				return
			}
		case jAfter:
			switch {
			case isSpace(c):
			case c == ',':
				if s.stack[len(s.stack)-1].array {
					s.st = jValue
				} else {
					s.st = jObjKey
				}
			case c == '}' || c == ']':
				s.closeContainer(c == ']')
			default:
				s.st = jFail
				return
			}
		case jDone:
			// Another document may follow (newline-delimited JSON).
			if !isSpace(c) {
				s.startValue(c)
			}
		case jFail:
			return
		}
		if s.st == jFail {
			return
		}
	}
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (s *jsonScanner) add(p []byte) {
	if s.over || len(p) == 0 {
		return
	}
	lim := maxValue
	if s.isKey {
		lim = maxKey
	}
	if len(s.buf)+len(p) > lim {
		s.over = true
		return
	}
	s.buf = append(s.buf, p...)
}

// maxStack is how deeply containers may nest before the scanner gives up,
// so a body of nothing but "[" can't grow its stack.
const maxStack = 256

func (s *jsonScanner) startValue(c byte) {
	path, depth := s.valuePath()
	switch c {
	case '{', '[':
		if len(s.stack) >= maxStack {
			s.st = jFail
			return
		}
		// {"error": {...}} is how services report a failure inside a 2xx
		// body or stream; "error": null is a success.
		if c == '{' && depth == 1 && path == "error" {
			s.failed = true
		}
		// Arrays don't add to the path: their elements share it.
		s.stack = append(s.stack, frame{array: c == '[', depth: depth, path: path})
		if c == '[' {
			s.st = jArrayFirst
		} else {
			s.st = jObjFirst
		}
		return
	}
	s.slot = -1
	if path != noPath {
		if i, ok := s.targets[path]; ok {
			s.slot = i
		}
	}
	s.isKey, s.esc, s.uni, s.buf, s.over = false, false, 0, s.buf[:0], s.slot < 0
	switch {
	case c == '"':
		s.st = jString
	case c == '-' || c >= '0' && c <= '9' || c == 't' || c == 'f' || c == 'n':
		s.add([]byte{c})
		s.st = jScalar
	default:
		s.st = jFail
	}
}

func (s *jsonScanner) stringByte(c byte) {
	switch {
	case s.uni > 0:
		s.uni--
	case s.esc:
		s.esc = false
		switch c {
		case 'u':
			s.uni, s.over = 4, true // names we read are plain ASCII
		case 'n', 't', 'r', 'b', 'f':
			s.over = true
		default: // \" \\ \/
			s.add([]byte{c})
		}
	case c == '\\':
		s.esc = true
	case c == '"':
		s.endString()
	default:
		s.add([]byte{c})
	}
}

func (s *jsonScanner) endString() {
	if s.isKey {
		top := &s.stack[len(s.stack)-1]
		switch {
		case s.over:
			top.child = noPath
		case top.depth == 0 && top.path == "":
			top.child = string(s.buf)
		default:
			top.child = top.path + "." + string(s.buf)
		}
		s.st = jColon
		return
	}
	if s.slot >= 0 && !s.over {
		s.vals[s.slot] = value{set: true, str: string(s.buf)}
	}
	s.afterValue()
}

func (s *jsonScanner) endScalar() {
	if s.slot >= 0 && !s.over {
		if f, ok := parseNumber(string(s.buf)); ok {
			s.vals[s.slot] = value{set: true, isNum: true, num: f, str: string(s.buf)}
		}
	}
	s.afterValue()
}

func (s *jsonScanner) afterValue() {
	s.slot = -1
	if len(s.stack) == 0 {
		s.st = jDone
	} else {
		s.st = jAfter
	}
}

func (s *jsonScanner) closeContainer(array bool) {
	if len(s.stack) == 0 || s.stack[len(s.stack)-1].array != array {
		s.st = jFail
		return
	}
	s.stack = s.stack[:len(s.stack)-1]
	s.afterValue()
}

// finish ends input: a root number has no delimiter after it. One inside
// a container was cut off and may be missing digits, so it's dropped.
func (s *jsonScanner) finish() {
	if s.st == jScalar && len(s.stack) == 0 {
		s.endScalar()
	}
}

// sseParser feeds the data of each server-sent event to a JSON scanner,
// one document per event, without holding a line or an event.
type sseParser struct {
	js       *jsonScanner
	st       uint8 // sseLineStart, sseField, sseValueStart, sseValue, sseSkip
	field    [8]byte
	nField   int
	dataSeen bool // the current event has a data line already
	lastCR   bool
	event    [16]byte // the current event's name, if short
	nEvent   int      // its length, -1 if too long
}

// failedEvents are event names that report the request failed: OpenAI's
// Responses stream and Anthropic's stream use them.
var failedEvents = map[string]bool{"error": true, "response.failed": true}

const (
	sseLineStart uint8 = iota
	sseField
	sseValueStart
	sseValue
	sseSkip
	sseEventStart
	sseEvent
)

func (p *sseParser) feed(b []byte) {
	for i := 0; i < len(b); i++ {
		c := b[i]
		if p.lastCR {
			p.lastCR = false
			if c == '\n' {
				continue
			}
		}
		if c == '\r' || c == '\n' {
			p.endLine()
			p.lastCR = c == '\r'
			continue
		}
		switch p.st {
		case sseLineStart:
			if c == ':' {
				p.st = sseSkip // a comment
				continue
			}
			p.nField, p.st = 0, sseField
			p.fieldByte(c)
		case sseField:
			p.fieldByte(c)
		case sseValueStart, sseEventStart:
			if p.st == sseValueStart {
				p.st = sseValue
			} else {
				p.st = sseEvent
			}
			if c == ' ' {
				continue
			}
			fallthrough
		case sseValue, sseSkip, sseEvent:
			j := i
			for j < len(b) && b[j] != '\r' && b[j] != '\n' {
				j++
			}
			switch p.st {
			case sseValue:
				p.js.feed(b[i:j])
			case sseEvent:
				p.eventBytes(b[i:j])
			}
			i = j - 1
		}
	}
}

func (p *sseParser) fieldByte(c byte) {
	if c == ':' {
		switch string(p.field[:p.nField]) {
		case "data":
			p.dataLine()
			p.st = sseValueStart
		case "event":
			p.nEvent = 0
			p.st = sseEventStart
		default:
			p.st = sseSkip
		}
		return
	}
	if p.nField == len(p.field) {
		p.st = sseSkip
		return
	}
	p.field[p.nField] = c
	p.nField++
}

func (p *sseParser) eventBytes(b []byte) {
	if p.nEvent < 0 || p.nEvent+len(b) > len(p.event) {
		p.nEvent = -1
		return
	}
	p.nEvent += copy(p.event[p.nEvent:], b)
}

func (p *sseParser) dataLine() {
	if p.dataSeen {
		p.js.feed([]byte{'\n'}) // data lines of one event join with a newline
	} else {
		p.js.reset()
	}
	p.dataSeen = true
}

func (p *sseParser) endLine() {
	switch p.st {
	case sseLineStart: // a blank line ends the event
		if p.dataSeen {
			p.js.finish()
		}
		if p.nEvent > 0 && failedEvents[string(p.event[:p.nEvent])] {
			p.js.failed = true
		}
		p.dataSeen, p.nEvent = false, 0
	case sseField: // a field with no colon has an empty value
		if string(p.field[:p.nField]) == "data" {
			p.dataLine()
		}
	}
	p.st = sseLineStart
}

func (p *sseParser) finish() {
	if p.dataSeen {
		p.js.finish()
	}
	if p.nEvent > 0 && failedEvents[string(p.event[:p.nEvent])] {
		p.js.failed = true
	}
}

// jsonNumber is JSON's number grammar. ParseFloat alone would also take
// "1.", "0x1p4", "nan" and "inf", which the hosted edge's port wouldn't.
var jsonNumber = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// parseNumber reads a JSON number; one too large for a float64 isn't read.
func parseNumber(s string) (float64, bool) {
	if !jsonNumber.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

// isJSON and isSSE pick a parser by Content-Type.
func isSSE(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/event-stream")
}

func isJSON(ct string) bool {
	mt, _, _ := strings.Cut(strings.ToLower(ct), ";")
	mt = strings.TrimSpace(mt)
	return mt == "application/json" || strings.HasSuffix(mt, "+json") || mt == "application/x-ndjson"
}
