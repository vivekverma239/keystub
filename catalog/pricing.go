package catalog

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

//go:embed pricing.json
var pricingJSON []byte

// Price is one model's list price from a date on, in US dollars per
// million tokens (per unit for Units).
type Price struct {
	// Models are API model names as the service returns them. A name
	// ending in "*" covers every model starting with the rest
	// ("claude-sonnet-4-5*" for its dated snapshots); an exact name wins
	// over a pattern, and a longer pattern over a shorter one.
	Models []string `json:"models"`
	// Effective is the first day (UTC) the price applies. The earliest
	// price listed for a model also covers any time before it.
	Effective string  `json:"effective"`
	Input     float64 `json:"input"`
	// CachedInput and CacheWrite default to Input when not set.
	CachedInput *float64 `json:"cachedInput,omitempty"`
	CacheWrite  *float64 `json:"cacheWrite,omitempty"`
	Output      float64  `json:"output"`
	Unit        float64  `json:"unit,omitempty"`
	// Above is a higher tier for requests whose input passes a number of
	// tokens (long context).
	Above *struct {
		InputTokens int64    `json:"inputTokens"`
		Input       float64  `json:"input"`
		CachedInput *float64 `json:"cachedInput,omitempty"`
		CacheWrite  *float64 `json:"cacheWrite,omitempty"`
		Output      float64  `json:"output"`
	} `json:"above,omitempty"`
	// OffPeak discounts requests outside the provider's peak hours.
	OffPeak *OffPeak `json:"offPeak,omitempty"`
	Source  string   `json:"source"`  // the provider's pricing page
	Checked string   `json:"checked"` // the day someone read Source
	Note    string   `json:"note,omitempty"`

	from time.Time
}

// OffPeak is a discount outside peak hours: prices are multiplied by
// Factor unless the request's UTC weekday (0 Sunday … 6 Saturday) is in
// PeakWeekdays and its UTC hour h is in a [start, end) of PeakHoursUTC.
type OffPeak struct {
	Factor       float64  `json:"factor"`
	PeakWeekdays []int    `json:"peakWeekdays"`
	PeakHoursUTC [][2]int `json:"peakHoursUtc"`
}

func (o *OffPeak) peak(at time.Time) bool {
	at = at.UTC()
	wd := int(at.Weekday())
	inDay := false
	for _, d := range o.PeakWeekdays {
		inDay = inDay || d == wd
	}
	if !inDay {
		return false
	}
	for _, r := range o.PeakHoursUTC {
		if at.Hour() >= r[0] && at.Hour() < r[1] {
			return true
		}
	}
	return false
}

// Pricing is pricing.json: list prices per service.
type Pricing struct {
	Version  int                `json:"version"`
	Currency string             `json:"currency"`
	Services map[string][]Price `json:"services"`
}

// Prices is the built-in pricing.json.
var Prices = mustPricing(pricingJSON)

func mustPricing(b []byte) *Pricing {
	p, err := LoadPricing(b)
	if err != nil {
		panic(err)
	}
	return p
}

// LoadPricing parses and validates a pricing file.
func LoadPricing(b []byte) (*Pricing, error) {
	var p Pricing
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("pricing: %w", err)
	}
	if p.Currency != "USD" {
		return nil, errors.New("pricing: currency must be USD")
	}
	for svc, prices := range p.Services {
		seen := map[string]bool{}
		for i := range prices {
			pr := &prices[i]
			t, err := time.Parse(time.DateOnly, pr.Effective)
			if err != nil {
				return nil, fmt.Errorf("pricing: %s: effective %q: %w", svc, pr.Effective, err)
			}
			if _, err := time.Parse(time.DateOnly, pr.Checked); err != nil {
				return nil, fmt.Errorf("pricing: %s: checked %q: %w", svc, pr.Checked, err)
			}
			pr.from = t
			if len(pr.Models) == 0 {
				return nil, fmt.Errorf("pricing: %s: an entry without models", svc)
			}
			if !strings.HasPrefix(pr.Source, "https://") {
				return nil, fmt.Errorf("pricing: %s %s: source must be an https URL", svc, pr.Models[0])
			}
			neg := pr.Input < 0 || pr.Output < 0 || pr.Unit < 0 || pr.CachedInput != nil && *pr.CachedInput < 0 || pr.CacheWrite != nil && *pr.CacheWrite < 0
			if a := pr.Above; a != nil {
				neg = neg || a.InputTokens <= 0 || a.Input < 0 || a.Output < 0 || a.CachedInput != nil && *a.CachedInput < 0 || a.CacheWrite != nil && *a.CacheWrite < 0
			}
			if o := pr.OffPeak; o != nil {
				neg = neg || o.Factor <= 0 || o.Factor > 1 || len(o.PeakWeekdays) == 0 || len(o.PeakHoursUTC) == 0
				for _, d := range o.PeakWeekdays {
					neg = neg || d < 0 || d > 6
				}
				for _, r := range o.PeakHoursUTC {
					neg = neg || r[0] < 0 || r[1] > 24 || r[0] >= r[1]
				}
			}
			if neg {
				return nil, fmt.Errorf("pricing: %s %s: negative price, or a bad tier or off-peak", svc, pr.Models[0])
			}
			for _, m := range pr.Models {
				if m == "" || m == "*" || strings.Contains(strings.TrimSuffix(m, "*"), "*") {
					return nil, fmt.Errorf("pricing: %s: model %q (one trailing * at most)", svc, m)
				}
				if k := m + "@" + pr.Effective; seen[k] {
					return nil, fmt.Errorf("pricing: %s: %s listed twice from %s", svc, m, pr.Effective)
				} else {
					seen[k] = true
				}
			}
		}
	}
	return &p, nil
}

// Lookup returns the price of a service's model at a time: the entry whose
// model name matches best (exact, else the longest pattern), and of those
// the latest effective on or before at, else the earliest.
func (p *Pricing) Lookup(service, model string, at time.Time) (Price, bool) {
	if p == nil || model == "" {
		return Price{}, false
	}
	best, bestLen := "", -1
	for _, pr := range p.Services[service] {
		for _, m := range pr.Models {
			l := -1
			if m == model {
				l = math.MaxInt
			} else if base, ok := strings.CutSuffix(m, "*"); ok && strings.HasPrefix(model, base) {
				l = len(base)
			}
			if l > bestLen {
				best, bestLen = m, l
			}
		}
	}
	if bestLen < 0 {
		return Price{}, false
	}
	var cands []Price
	for _, pr := range p.Services[service] {
		for _, m := range pr.Models {
			if m == best {
				cands = append(cands, pr)
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].from.Before(cands[j].from) })
	chosen := cands[0]
	for _, c := range cands {
		if !c.from.After(at) {
			chosen = c
		}
	}
	return chosen, true
}

// CostMicros prices a request made at a time, in US dollars × 10⁶,
// rounded to the nearest. input counts every input token, cached and cache
// writes included.
func (pr Price) CostMicros(at time.Time, input, cached, cacheWrite, output, units int64) int64 {
	in, out := pr.Input, pr.Output
	cin, cw := pr.CachedInput, pr.CacheWrite
	if a := pr.Above; a != nil && input > a.InputTokens {
		in, out, cin, cw = a.Input, a.Output, a.CachedInput, a.CacheWrite
	}
	cinV, cwV := in, in
	if cin != nil {
		cinV = *cin
	}
	if cw != nil {
		cwV = *cw
	}
	plain := max(input-cached-cacheWrite, 0)
	// $ per million tokens is µ$ per token.
	c := float64(plain)*in + float64(cached)*cinV + float64(cacheWrite)*cwV + float64(output)*out + float64(units)*pr.Unit*1e6
	if pr.OffPeak != nil && !pr.OffPeak.peak(at) {
		c *= pr.OffPeak.Factor
	}
	return int64(math.Round(c))
}
