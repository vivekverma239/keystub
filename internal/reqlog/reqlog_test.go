package reqlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecentNewestFirst(t *testing.T) {
	l, _ := Open("", 3)
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		l.Add(Entry{Path: p})
	}
	got := l.Recent(10)
	if len(got) != 3 || got[0].Path != "/d" || got[2].Path != "/b" {
		t.Fatalf("got %+v", got)
	}
}

func TestRotatesAndStopsAfterClose(t *testing.T) {
	old := maxFileSize
	maxFileSize = 200
	defer func() { maxFileSize = old }()
	path := filepath.Join(t.TempDir(), "requests.jsonl")
	l, err := Open(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		l.Add(Entry{Path: "/some/longer/path", Service: "openai"})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("log never rotated")
	}
	if st, _ := os.Stat(path); st.Size() > maxFileSize {
		t.Fatalf("current file is %d bytes", st.Size())
	}
	_ = l.Close()
	before, _ := os.Stat(path)
	l.Add(Entry{Path: "/late"})
	after, _ := os.Stat(path)
	if after.Size() != before.Size() {
		t.Fatal("Add wrote after Close")
	}
}
