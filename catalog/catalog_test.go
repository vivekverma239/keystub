package catalog

import (
	"strings"
	"testing"
)

func TestServicesJSONLoads(t *testing.T) {
	if len(Presets) == 0 {
		t.Fatal("no presets")
	}
	for _, p := range Presets {
		if p.Name == "" || p.Header == "" || !strings.Contains(p.Format, "{key}") {
			t.Errorf("%s is incomplete: %+v", p.ID, p)
		}
	}
	if o, ok := Preset("openai"); !ok || o.BaseURL.Var != "OPENAI_BASE_URL" || o.BaseURL.Path != "/v1" || o.PrimaryHost() != "api.openai.com" {
		t.Fatalf("openai = %+v", o)
	}
}

func TestLoadRejectsBadEntries(t *testing.T) {
	for name, src := range map[string]string{
		"duplicate":   `{"services":[{"id":"a","name":"A","hosts":["a.com"]},{"id":"a","name":"A","hosts":["a.com"]}]}`,
		"no hosts":    `{"services":[{"id":"a","name":"A"}]}`,
		"bad var":     `{"services":[{"id":"a","name":"A","hosts":["a.com"],"baseUrl":{"var":"NOT VALID"}}]}`,
		"bad path":    `{"services":[{"id":"a","name":"A","hosts":["a.com"],"baseUrl":{"var":"A_URL","path":"v1"}}]}`,
		"host is url": `{"services":[{"id":"a","name":"A","hosts":["https://a.com"]}]}`,
	} {
		if _, err := Load([]byte(src)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := Load([]byte(`{"services":[{"id":"a","name":"A","hosts":["a.com"]}]}`))
	if err != nil || s[0].Header != "Authorization" || s[0].Format != "Bearer {key}" {
		t.Fatalf("defaults: %+v, %v", s, err)
	}
}

func TestNoTwoServicesClaimAHost(t *testing.T) {
	owner := map[string]string{}
	for _, p := range Presets {
		for _, h := range p.Hosts {
			if prev, ok := owner[h]; ok {
				t.Errorf("%s is claimed by %s and %s", h, prev, p.ID)
			}
			owner[h] = p.ID
		}
	}
	// A wildcard must not cover another service's plain host either.
	for _, p := range Presets {
		for h, id := range owner {
			if id != p.ID && !strings.HasPrefix(h, "*.") && p.Matches(h) {
				t.Errorf("%s (of %s) is also matched by %s", h, id, p.ID)
			}
		}
	}
	for _, p := range Presets {
		if !strings.HasPrefix(p.Docs, "https://") {
			t.Errorf("%s: docs %q", p.ID, p.Docs)
		}
	}
}
