// Package legacy keeps installs from before the rename from Stubkey to
// Keystub working: STUBKEY_* variables, the ~/.stubkey folder, stubkey.db
// and the old Keychain items are still found, and the new names win.
package legacy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Getenv returns $name. For a KEYSTUB_ variable that is unset or empty, it
// returns the old STUBKEY_ one instead.
func Getenv(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	if rest, ok := strings.CutPrefix(name, "KEYSTUB_"); ok {
		return os.Getenv("STUBKEY_" + rest)
	}
	return ""
}

// Home returns ~/.keystub, or ~/.stubkey when only the old folder exists.
func Home(userHome string) string {
	dir := filepath.Join(userHome, ".keystub")
	old := filepath.Join(userHome, ".stubkey")
	if !exists(dir) && exists(old) {
		return old
	}
	return dir
}

// File returns dir/name, or dir/old when only the old file exists.
func File(dir, name, old string) string {
	p := filepath.Join(dir, name)
	if o := filepath.Join(dir, old); !exists(p) && exists(o) {
		return o
	}
	return p
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}
