package swap

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
)

type swapCase struct {
	Name     string            `json:"name"`
	Service  string            `json:"service"`
	Request  map[string]string `json:"request"`
	RealKey  string            `json:"realKey"`
	Token    string            `json:"token"`
	Upstream map[string]string `json:"upstream"`
	Refused  bool              `json:"refused"`
}

// TestConformance runs the cases every Keystub data plane must pass.
func TestConformance(t *testing.T) {
	b, err := os.ReadFile("../../conformance/swap.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AuthHeaders []string   `json:"authHeaders"`
		Cases       []swapCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	if !slices.Equal(f.AuthHeaders, AuthHeaders) {
		t.Fatalf("authHeaders in swap.json %v, in Go %v", f.AuthHeaders, AuthHeaders)
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			svc, ok := catalog.Preset(c.Service)
			if !ok {
				t.Fatalf("no service %q in the catalog", c.Service)
			}
			h := http.Header{}
			for k, v := range c.Request {
				h.Set(k, v)
			}
			if stray := Stray(h, svc.Header); (len(stray) > 0) != c.Refused {
				t.Fatalf("Stray = %v, refused = %v", stray, c.Refused)
			}
			if c.Refused {
				return
			}
			if got := Find(h, svc.Header); got != c.Token {
				t.Fatalf("Find = %q, want %q", got, c.Token)
			}
			Apply(h, c.RealKey, svc.Header, svc.Format)
			for k, want := range c.Upstream {
				if got := h.Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			if left := Find(h, svc.Header); left != "" || len(Stray(h, svc.Header)) > 0 {
				t.Errorf("a proxy token is still in the request: %q", left)
			}
		})
	}
}

func TestTokenPicksTheEarliest(t *testing.T) {
	if got := token("skstubaa then sk-stub-bb"); got != "skstubaa" {
		t.Fatalf("got %q", got)
	}
	if got := token("sk-stub- nothing, then sk-stub-cc"); got != "sk-stub-cc" {
		t.Fatalf("got %q", got)
	}
}

func TestRealKeyThatLooksLikeAToken(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer sk-stub-aa"}}
	Apply(h, "sk-stub-bb", "Authorization", "Bearer {key}")
	if got := h.Get("Authorization"); got != "Bearer sk-stub-bb" {
		t.Fatalf("got %q", got)
	}
}

func TestIn(t *testing.T) {
	tok := core.TokenPrefix + "0123456789abcdef0123456789abcdef0123"
	for in, want := range map[string]string{
		"Bearer " + tok:        tok,
		tok:                    tok,
		"token " + tok + " x":  tok,
		"Bearer sk-live-other": "",
	} {
		if got := In(in); got != want {
			t.Errorf("In(%q) = %q", in, got)
		}
	}
}
