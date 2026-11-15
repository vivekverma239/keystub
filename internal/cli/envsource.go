package cli

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Where keystub init reads a project's variables from, when it isn't
// given --env-file: the first dotenv file the folder has, else the
// variables its code reads. An example file's values are placeholders, so
// only its names are taken.

// envSource is what init found: the variables and, from a real dotenv
// file, their values.
type envSource struct {
	File    string            // the dotenv file read, or "" for code
	Kind    string            // "file", "example" or "code"
	Names   []string          // in the order found
	Values  map[string]string // a "file" source's only
	FoundIn map[string]string // a "code" source's: the first file reading each
}

// dotenvCandidates are tried in order. Real values come before examples.
var dotenvCandidates = []struct{ name, kind string }{
	{".env", "file"},
	{".env.local", "file"},
	{".env.development.local", "file"},
	{".env.development", "file"},
	{".env.example", "example"},
	{".env.sample", "example"},
	{".env.template", "example"},
}

// findEnvSource looks in dir for the project's variables.
func findEnvSource(dir string) (envSource, error) {
	for _, cand := range dotenvCandidates {
		path := filepath.Join(dir, cand.name)
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			continue
		}
		names, values, err := dotenvNames(path)
		if err != nil {
			return envSource{}, err
		}
		src := envSource{File: path, Kind: cand.kind, Names: names, Values: values}
		if cand.kind == "example" {
			src.Values = map[string]string{}
		}
		return src, nil
	}
	names, found := scanCode(dir)
	return envSource{Kind: "code", Names: names, Values: map[string]string{}, FoundIn: found}, nil
}

// The ways code reads a variable, in the languages a project is likely in.
var envReads = regexp.MustCompile(strings.Join([]string{
	`process\.env\.([A-Z_][A-Z0-9_]*)`,
	`process\.env\[\s*["'` + "`" + `]([A-Z_][A-Z0-9_]*)["'` + "`" + `]\s*\]`,
	`import\.meta\.env\.([A-Z_][A-Z0-9_]*)`,
	`Deno\.env\.get\(\s*["']([A-Z_][A-Z0-9_]*)["']`,
	`os\.environ\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\]`,
	`os\.environ\.get\(\s*["']([A-Z_][A-Z0-9_]*)["']`,
	`os\.getenv\(\s*["']([A-Z_][A-Z0-9_]*)["']`,
	`os\.Getenv\(\s*"([A-Z_][A-Z0-9_]*)"`,
	`os\.LookupEnv\(\s*"([A-Z_][A-Z0-9_]*)"`,
	`ENV\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\]`,
	`ENV\.fetch\(\s*["']([A-Z_][A-Z0-9_]*)["']`,
	`env::var\(\s*"([A-Z_][A-Z0-9_]*)"`,
	`getenv\(\s*["']([A-Z_][A-Z0-9_]*)["']`,
}, "|"))

var codeExts = map[string]bool{
	".ts": true, ".tsx": true, ".js": true, ".jsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true,
	".py": true, ".go": true, ".rb": true, ".rs": true, ".php": true, ".ex": true, ".exs": true,
	".svelte": true, ".vue": true, ".astro": true,
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true, "out": true, ".next": true,
	".nuxt": true, ".svelte-kit": true, ".turbo": true, ".vercel": true, ".wrangler": true, "target": true,
	"venv": true, ".venv": true, "__pycache__": true, ".mypy_cache": true, ".pytest_cache": true, "coverage": true,
}

// Names the machine, the shell or a framework sets: never a project's own.
var ambient = map[string]bool{
	"NODE_ENV": true, "HOME": true, "PATH": true, "PWD": true, "USER": true, "SHELL": true, "TMPDIR": true, "TERM": true,
	"CI": true, "PORT": true, "HOST": true, "HOSTNAME": true, "DEBUG": true, "LANG": true, "TZ": true,
	"VERCEL": true, "VERCEL_ENV": true, "VERCEL_URL": true, "NEXT_RUNTIME": true, "DEV": true, "PROD": true, "MODE": true,
	"SSR": true, "BASE_URL": true,
}

const maxScanFiles = 5000

// scanCode lists the variables the code under dir reads, each with the
// first file (relative to dir) that reads it.
func scanCode(dir string) ([]string, map[string]string) {
	found := map[string]string{}
	files := 0
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if path != dir && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !codeExts[filepath.Ext(path)] || strings.HasSuffix(path, ".d.ts") {
			return nil
		}
		if files++; files > maxScanFiles {
			return filepath.SkipAll
		}
		if info, err := d.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		rel, _ := filepath.Rel(dir, path)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			for _, m := range envReads.FindAllStringSubmatch(sc.Text(), -1) {
				for _, g := range m[1:] {
					if g != "" && !ambient[g] && !strings.HasPrefix(g, "npm_") {
						if _, ok := found[g]; !ok {
							found[g] = rel
						}
					}
				}
			}
		}
		return nil
	})
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, found
}

// publicPrefixes are variables a framework ships to the browser: never a
// secret, whatever they're called.
var publicPrefixes = []string{"NEXT_PUBLIC_", "VITE_", "PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "GATSBY_"}

var secretName = regexp.MustCompile(`(^|_)(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|PRIVATE|CREDENTIALS?|DSN|SIGNING|WEBHOOK)(_|$)`)

// passwordURL is a connection string with a password in it.
var passwordURL = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^/\s:@]*:[^@\s]+@`)

// looksSecret says whether a variable that no service reads is a secret
// to keep in Keystub (a database URL, a deploy key, a signing secret)
// rather than plain configuration (a port, a feature flag, a public URL).
func looksSecret(name, value string) bool {
	upper := strings.ToUpper(name)
	for _, p := range publicPrefixes {
		if strings.HasPrefix(upper, p) {
			return false
		}
	}
	if ambient[upper] {
		return false
	}
	if passwordURL.MatchString(strings.TrimSpace(value)) {
		return true
	}
	if strings.HasSuffix(upper, "DATABASE_URL") || strings.HasSuffix(upper, "_DB_URL") || strings.HasSuffix(upper, "REDIS_URL") {
		return true
	}
	return secretName.MatchString(upper)
}

// isPostgresURL is a value the Postgres service can hold.
func isPostgresURL(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "postgres://") || strings.HasPrefix(v, "postgresql://")
}

// localSlug is the server's slug of a name, for naming a service before
// it's made: lower case, runs of anything else one dash.
func localSlug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// inCatalog says whether id is a catalog service (Postgres), which is
// added from the catalog, not made.
func inCatalog(reads map[string]reader, id string) bool {
	for _, r := range reads {
		if !r.added && r.service.ID == id {
			return true
		}
	}
	return false
}
