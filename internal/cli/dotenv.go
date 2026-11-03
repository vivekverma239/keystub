package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A dotenv file (.env, .env.local, .dev.vars): lines of NAME=value or
// export NAME=value. A value is bare (ending at " #"), 'single-quoted'
// (as is) or "double-quoted" (with \n, \" and \\ escapes); quoted values
// may span lines. The CLI reads a key from one with --env-file, so the
// value never passes through a shell, and writes a token into one with
// --write-env, so the token is never printed. It is never run as shell.
// Before it writes one it asks, and keeps a copy of the old file in
// ~/.keystub/backups.

var dotenvName = regexp.MustCompile(`^[ \t]*(export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*`)

// dotenvEntry is one variable's definition: lines [start, end) of the
// file, its name, and its value.
type dotenvEntry struct {
	start, end int
	prefix     string // what comes before the value: "export NAME=" as written
	name       string
	value      string
	// bad says why the value can't be read: its quotes don't close
	// cleanly, so loaders disagree on it. Such an entry is its first line
	// alone, as npm's dotenv reads it, and the lines after it are their
	// own. unclear is a value that parses but that loaders read
	// differently (a bare #, a $ some expand): only reading refuses it.
	bad, unclear string
}

// parseDotenv finds every definition in a file's lines. Lines that aren't
// one (comments, blanks, anything else) belong to no entry.
func parseDotenv(lines []string) []dotenvEntry {
	var out []dotenvEntry
	for i := 0; i < len(lines); i++ {
		m := dotenvName.FindStringSubmatchIndex(lines[i])
		if m == nil {
			continue
		}
		e := dotenvEntry{start: i, end: i + 1, prefix: lines[i][:m[1]], name: lines[i][m[4]:m[5]]}
		rest := strings.TrimRight(lines[i][m[1]:], "\r")
		switch {
		case rest != "" && strings.ContainsRune("\"'`", rune(rest[0])):
			q := rest[0]
			text := rest[1:]
			for {
				if v, after, ok := closeQuote(text, q); ok {
					if t := strings.TrimLeft(after, " \t"); t != "" && !strings.HasPrefix(t, "#") {
						e.bad = "has text after its closing quote"
					}
					e.value = v
					break
				}
				if e.end == len(lines) {
					e.bad = "has no closing quote"
					break
				}
				text += "\n" + strings.TrimRight(lines[e.end], "\r")
				e.end++
			}
			if e.bad != "" {
				e.end, e.value = i+1, ""
			} else if q != '\'' && strings.Contains(e.value, "$") {
				e.unclear = "has a $ that some dotenv loaders expand; put the value in single quotes"
			}
		default:
			// A # after a space starts a comment for every loader; one
			// inside a bare value ends it for some and not others.
			if j := strings.IndexAny(rest, "#"); j == 0 {
				rest = ""
			} else if j > 0 && (rest[j-1] == ' ' || rest[j-1] == '\t') {
				rest = rest[:j]
			} else if j > 0 {
				e.unclear = "has a # that dotenv loaders read differently; put the value in quotes"
			}
			e.value = strings.TrimSpace(rest)
			if strings.Contains(e.value, "$") {
				e.unclear = "has a $ that some dotenv loaders expand; put the value in single quotes"
			}
		}
		out = append(out, e)
		i = e.end - 1
	}
	return out
}

// closeQuote reads a quoted value up to its closing quote q, returning
// what follows that quote, or reports there is none in text. Only
// double quotes have escapes.
func closeQuote(text string, q byte) (value, after string, ok bool) {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == q:
			return b.String(), text[i+1:], true
		case q == '"' && c == '\\' && i+1 < len(text):
			i++
			switch text[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(text[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}

// dotenvValue is name's value in the dotenv file at path: its last
// definition, as dotenv loaders read it.
func dotenvValue(path, name string) (string, error) {
	lines, err := readLines(path)
	if err != nil {
		return "", fmt.Errorf("can't read %s: %v", path, unwrapPathError(err))
	}
	var last *dotenvEntry
	for _, e := range parseDotenv(lines) {
		if e.name == name {
			last = &e // a fresh e each round
		}
	}
	switch {
	case last == nil:
		return "", usageErr("%s doesn't set %s", path, name)
	case last.bad != "":
		return "", usageErr("%s's value in %s %s", name, path, last.bad)
	case last.unclear != "":
		return "", usageErr("%s's value in %s %s", name, path, last.unclear)
	case strings.TrimSpace(last.value) == "":
		return "", usageErr("%s is empty in %s", name, path)
	}
	return last.value, nil
}

// dotenvNames lists the variables a dotenv file sets, in order, once each.
func dotenvNames(path string) ([]string, map[string]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, nil, fmt.Errorf("can't read %s: %v", path, unwrapPathError(err))
	}
	var names []string
	values := map[string]string{}
	for _, e := range parseDotenv(lines) {
		if _, seen := values[e.name]; !seen {
			names = append(names, e.name)
		}
		values[e.name] = e.value
	}
	return names, values, nil
}

// setDotenv sets each variable in the dotenv file at path, in place where
// the file defines it (every definition) and at the end where it
// doesn't. It makes the file, readable by its owner alone, if there is
// none, keeps an existing file's mode, and writes through a symlink.
// The swap is atomic: a reader sees the old file or the new one.
func setDotenv(path string, vars []envVar) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	mode := fs.FileMode(0o600)
	lines, err := readLines(path)
	switch {
	case err == nil:
		if st, err := os.Stat(path); err == nil {
			mode = st.Mode().Perm()
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("can't read %s: %v", path, unwrapPathError(err))
	}
	want := map[string]string{}
	for _, v := range vars {
		want[v.name] = v.value
	}
	done := map[string]bool{}
	var out []string
	next := 0
	for _, e := range parseDotenv(lines) {
		out = append(out, lines[next:e.start]...)
		next = e.end
		v, ok := want[e.name]
		if !ok {
			out = append(out, lines[e.start:e.end]...)
			continue
		}
		out = append(out, e.prefix+dotenvQuote(v)+eol(lines[e.end-1]))
		done[e.name] = true
	}
	out = append(out, lines[next:]...)
	crlf := ""
	if len(lines) > 0 {
		crlf = eol(lines[0])
	}
	for _, v := range vars {
		if !done[v.name] {
			out = append(out, v.name+"="+dotenvQuote(v.value)+crlf)
			done[v.name] = true
		}
	}
	if crlf != "" { // a CRLF file's last line may have had no line end
		for i, l := range out {
			out[i] = strings.TrimSuffix(l, "\r") + "\r"
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".keystub-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(strings.Join(out, "\n") + "\n")
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync() // the new file is whole before it takes the old one's place
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

type envVar struct{ name, value string }

// backupDir is where a dotenv file goes before Keystub rewrites it:
// under the CLI's own folder, readable by its owner alone, and never
// inside the project, where it could be committed with the real keys.
func (c *ctx) backupDir() string { return filepath.Join(c.Home, "backups") }

// backupDotenv copies the dotenv file at path into backupDir, named for
// the time and the file's full path, and returns the copy's path; ""
// when there's no file yet to keep.
func (c *ctx) backupDotenv(path string) (string, error) {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("can't read %s: %v", path, unwrapPathError(err))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(c.backupDir(), 0o700); err != nil {
		return "", err
	}
	// The time, the folder and file names (cut short), and a hash of the
	// full path, so two projects' .env files never share a name.
	sum := sha256.Sum256([]byte(abs))
	label := strings.Trim(backupUnsafe.ReplaceAllString(filepath.Base(filepath.Dir(abs))+"-"+filepath.Base(abs), "_"), "_")
	if len(label) > 80 {
		label = label[:80]
	}
	name := time.Now().Format("20060102-150405") + "-" + label + "-" + hex.EncodeToString(sum[:4])
	for i := 1; ; i++ {
		dst := filepath.Join(c.backupDir(), name)
		if i > 1 {
			dst += "-" + strconv.Itoa(i)
		}
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) && i < 100 {
			continue
		}
		if err != nil {
			return "", err
		}
		_, err = f.Write(b)
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
			return "", err
		}
		return dst, nil
	}
}

var backupUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// eol is a line's \r, so a CRLF file stays CRLF.
func eol(line string) string {
	if strings.HasSuffix(line, "\r") {
		return "\r"
	}
	return ""
}

// checkWritable makes sure setDotenv can write path, before anything is
// made that only the file will hold.
func checkWritable(path string) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if _, err := readLines(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return usageErr("can't read %s: %v", path, unwrapPathError(err))
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".keystub-*")
	if err != nil {
		return usageErr("can't write next to %s: %v", path, unwrapPathError(err))
	}
	f.Close()
	return os.Remove(f.Name())
}

var dotenvBare = regexp.MustCompile(`^[A-Za-z0-9_./:@+,=-]*$`)

// dotenvQuote writes a value bare when it can be, else double-quoted.
func dotenvQuote(v string) string {
	if dotenvBare.MatchString(v) {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
}

func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
