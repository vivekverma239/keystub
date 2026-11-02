package legacy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetenvFallsBackToTheOldName(t *testing.T) {
	t.Setenv("KEYSTUB_X_TEST", "")
	t.Setenv("STUBKEY_X_TEST", "old")
	if got := Getenv("KEYSTUB_X_TEST"); got != "old" {
		t.Fatalf("got %q", got)
	}
	t.Setenv("KEYSTUB_X_TEST", "new")
	if got := Getenv("KEYSTUB_X_TEST"); got != "new" {
		t.Fatalf("new name should win, got %q", got)
	}
	if got := Getenv("OTHER_X_TEST"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestHomeAndFile(t *testing.T) {
	h := t.TempDir()
	if got := Home(h); got != filepath.Join(h, ".keystub") {
		t.Fatalf("fresh: %s", got)
	}
	_ = os.Mkdir(filepath.Join(h, ".stubkey"), 0o700)
	if got := Home(h); got != filepath.Join(h, ".stubkey") {
		t.Fatalf("old only: %s", got)
	}
	_ = os.Mkdir(filepath.Join(h, ".keystub"), 0o700)
	if got := Home(h); got != filepath.Join(h, ".keystub") {
		t.Fatalf("both: %s", got)
	}

	d := t.TempDir()
	if got := File(d, "keystub.db", "stubkey.db"); got != filepath.Join(d, "keystub.db") {
		t.Fatalf("fresh: %s", got)
	}
	_ = os.WriteFile(filepath.Join(d, "stubkey.db"), nil, 0o600)
	if got := File(d, "keystub.db", "stubkey.db"); got != filepath.Join(d, "stubkey.db") {
		t.Fatalf("old only: %s", got)
	}
}
