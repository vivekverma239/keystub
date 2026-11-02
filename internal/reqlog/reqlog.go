// Package reqlog is the file Sink: it keeps recent entries in memory for the
// dashboard and appends every entry to a JSON-lines file. Entries never hold
// headers, query strings or bodies, so no key can end up in it.
package reqlog

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

// Entry is one proxied request.
type Entry = core.Entry

// maxFileSize is when the log file is rotated to "<path>.1".
var maxFileSize int64 = 10 << 20

// Log keeps the latest entries in memory and appends every entry to a file.
type Log struct {
	mu     sync.Mutex // guards the ring
	roll   *usage.Rollup
	totals *usage.Rollup // since this process started, so /metrics counters start at zero
	ring   []Entry
	next   int
	full   bool

	fmu    sync.Mutex // guards the file, so writes don't hold up Recent
	path   string
	f      *os.File
	size   int64
	closed bool
}

// Open appends to path (if not empty) and keeps the last size entries.
func Open(path string, size int) (*Log, error) {
	if size < 1 {
		size = 1
	}
	l := &Log{ring: make([]Entry, size), path: path, roll: usage.NewRollupKeeping(keepMetrics), totals: usage.NewTotals()}
	if path != "" {
		// Hourly metrics live in memory, rebuilt from the two files kept
		// (about 20 MiB of entries), so a restart can shorten history.
		for _, p := range []string{path + ".1", path} {
			l.replay(p)
		}
		if err := l.openFile(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

func (l *Log) openFile() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *Log) replay(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			l.roll.Add(e)
		}
	}
}

// Metrics answers a usage query from the entries since the older file
// began, or since start if that's earlier.
func (l *Log) Metrics(ctx context.Context, q usage.Query) ([]usage.Row, error) {
	return l.roll.Metrics(ctx, q)
}

// Totals returns counts since this process started.
func (l *Log) Totals(ctx context.Context) ([]usage.Row, error) {
	return l.totals.Totals(ctx)
}

// keepMetrics matches the SQLite store's hourly rows.
const keepMetrics = 400 * 24 * time.Hour

// Add records an entry.
func (l *Log) Add(e Entry) {
	l.roll.Add(e)
	l.totals.Add(e)
	l.mu.Lock()
	l.ring[l.next] = e
	l.next = (l.next + 1) % len(l.ring)
	if l.next == 0 {
		l.full = true
	}
	l.mu.Unlock()

	if l.path == "" {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.fmu.Lock()
	defer l.fmu.Unlock()
	if l.closed {
		return
	}
	if l.f != nil && l.size+int64(len(b)) > maxFileSize {
		l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".1")
	}
	if l.f == nil {
		if err := l.openFile(); err != nil {
			return
		}
	}
	n, _ := l.f.Write(b)
	l.size += int64(n)
}

// Recent returns up to n entries, newest first.
func (l *Log) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := l.next
	if l.full {
		count = len(l.ring)
	}
	if n > count {
		n = count
	}
	out := make([]Entry, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, l.ring[(l.next-i+len(l.ring))%len(l.ring)])
	}
	return out
}

// Close closes the file.
func (l *Log) Close() error {
	l.fmu.Lock()
	defer l.fmu.Unlock()
	l.closed = true
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
