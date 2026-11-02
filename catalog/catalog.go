// Package catalog holds the services Keystub knows out of the box. The
// list itself is services.json, shared with every other Keystub
// implementation, so they all add keys the same way.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vivekverma239/keystub/internal/core"
)

//go:embed services.json
var servicesJSON []byte

// Entry is one service as services.json describes it.
type Entry struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Docs     string   `json:"docs"`
	Note     string   `json:"note,omitempty"`
	Hosts    []string `json:"hosts"`
	// Auth names the service's own auth header, where a proxy token is
	// swapped like in Authorization, and how to send the key when the
	// client sent no proxy token.
	Auth struct {
		Header string `json:"header"`
		Format string `json:"format"`
	} `json:"auth"`
	BaseURL core.BaseURL `json:"baseUrl"`
	EnvVars []string     `json:"envVars"`
	// StatusPage is the provider's status page, for when requests fail.
	StatusPage string `json:"statusPage,omitempty"`
	// Usage says how to read what a request used from its response.
	Usage *Usage `json:"usage,omitempty"`
}

// Service turns an entry into the core's Service.
func (e Entry) Service() core.Service {
	return core.Service{
		ID: e.ID, Name: e.Name, Category: e.Category, Docs: e.Docs, Note: e.Note, Hosts: e.Hosts,
		Header: e.Auth.Header, Format: e.Auth.Format, BaseURL: e.BaseURL, EnvVars: e.EnvVars,
	}
}

// Presets are the services the dashboard can add in one click. Each one is
// an ordinary Service, so it can be edited after it's added.
var Presets, entries = mustLoad(servicesJSON)

func mustLoad(b []byte) ([]core.Service, []Entry) {
	s, e, err := loadEntries(b)
	if err != nil {
		panic(err)
	}
	return s, e
}

// Load parses and validates a catalog file.
func Load(b []byte) ([]core.Service, error) {
	s, _, err := loadEntries(b)
	return s, err
}

func loadEntries(b []byte) ([]core.Service, []Entry, error) {
	var f struct {
		Version  int     `json:"version"`
		Services []Entry `json:"services"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("catalog: %w", err)
	}
	seen := map[string]bool{}
	var out []core.Service
	for i, e := range f.Services {
		s := e.Service()
		if err := s.Validate(); err != nil {
			return nil, nil, fmt.Errorf("catalog: %s: %w", e.ID, err)
		}
		if seen[s.ID] {
			return nil, nil, fmt.Errorf("catalog: %s is listed twice", s.ID)
		}
		if e.StatusPage != "" && !strings.HasPrefix(e.StatusPage, "https://") {
			return nil, nil, fmt.Errorf("catalog: %s: statusPage must be an https URL", s.ID)
		}
		if e.Usage != nil {
			if err := e.Usage.validate(); err != nil {
				return nil, nil, fmt.Errorf("catalog: %s: usage: %w", s.ID, err)
			}
		}
		f.Services[i].ID = s.ID
		seen[s.ID] = true
		out = append(out, s)
	}
	return out, f.Services, nil
}

// Lookup returns the catalog entry with this ID, usage metadata included.
func Lookup(id string) (Entry, bool) {
	for _, e := range entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Preset returns the preset with this ID.
func Preset(id string) (core.Service, bool) {
	for _, p := range Presets {
		if p.ID == id {
			return p, true
		}
	}
	return core.Service{}, false
}
