// Package core is Keystub's hosting-independent centre: the types, the
// ports (interfaces) every adapter implements, and the Engine that decides,
// for each call, who is calling, which service it is for, whether it may go
// ahead, and which real key it gets. Core does no I/O of its own; storage,
// secrets, limits and logging all come in through ports.
//
// The model:
//
//	Saved key ── Limits            (a real key, stored once)
//	    ▲
//	    │ one per service
//	Project ──┬── Environment ──┬── Link (the saved key it uses for a service)
//	          │                 └── Token ── Limits
//	          └── Limits         └── Limits
//
// A token belongs to exactly one environment, and an environment links one
// saved key per service, so the environment decides which real key a
// request gets. Several environments can link the same saved key; rotating
// it changes them all at once.
package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// TokenPrefix starts every proxy token, so the proxy can find one in a header.
const TokenPrefix = "sk-stub-"

// CompactPrefix starts the dash-free form of a proxy token, for CLIs that
// reject "-" in a token (Vercel). Both forms name the same token.
const CompactPrefix = "skstub"

// Compact returns the dash-free form of a token.
func Compact(token string) string {
	return CompactPrefix + strings.TrimPrefix(token, TokenPrefix)
}

// Normalize turns either form of a token into the canonical one.
func Normalize(token string) string {
	if strings.HasPrefix(token, CompactPrefix) {
		return TokenPrefix + strings.TrimPrefix(token, CompactPrefix)
	}
	return token
}

var (
	ErrNotFound      = errors.New("not found")
	ErrNotLinked     = errors.New("this service has no saved key linked in this environment")
	ErrKeyInUse      = errors.New("this saved key is still linked")
	ErrKeyUnreadable = errors.New("the real key can't be decrypted")
	ErrNameTaken     = errors.New("name already in use")
	ErrUnknownKey    = errors.New("no valid proxy token")
	ErrExpired       = errors.New("this proxy token has expired")
	ErrNotAllowed    = errors.New("this proxy token can't use this service")
	ErrLimitReached  = errors.New("limit reached")
	ErrLinkPending   = errors.New("waiting for an admin to approve this machine")
	ErrLinkDenied    = errors.New("an admin turned this machine down")
	ErrLinkExpired   = errors.New("no such link request, or it expired")
	ErrTooManyLinks  = errors.New("too many machines are waiting to be approved; try again later")
)

// LimitError says which level's limit stopped a request.
type LimitError struct {
	Scope string // e.g. "project my-app", "token ci-agent"
	Kind  string // "daily" or "per-minute"
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("%s limit reached for %s", e.Kind, e.Scope)
}

func (e *LimitError) Unwrap() error { return ErrLimitReached }

// KeyInUseError refuses deleting a saved key that environments still link.
type KeyInUseError struct {
	Envs []string // the environments that link it, sorted
}

func (e *KeyInUseError) Error() string {
	return "this saved key is still linked in " + strings.Join(e.Envs, ", ") + "; unlink it there first"
}

func (e *KeyInUseError) Unwrap() error { return ErrKeyInUse }

// ServiceHasKeysError refuses changing a service that saved keys are for:
// its hosts decide where they are sent.
type ServiceHasKeysError struct {
	Service string
	Keys    []string // the saved keys' names, sorted
}

func (e *ServiceHasKeysError) Error() string {
	return "service " + e.Service + " has saved keys (" + strings.Join(e.Keys, ", ") + "); delete them before changing where its keys are sent"
}

func (e *ServiceHasKeysError) Unwrap() error { return ErrKeyInUse }

// Sealed is a value encrypted by a Sealer. Sealer names which one, so a
// store opened with the wrong sealer fails clearly instead of with garbage.
type Sealed struct {
	Sealer     string `json:"sealer,omitempty"` // "" means "envelope" (stage 0 data)
	WrappedKey []byte `json:"wrappedKey,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
}

// Limits apply at every level: project, environment, each token and each
// saved key. Zero means no limit at that level.
type Limits struct {
	DailyRequests int `json:"dailyRequests,omitempty"`
	PerMinute     int `json:"perMinute,omitempty"`
}

// Validate rejects negative limits.
func (l Limits) Validate() error {
	if l.DailyRequests < 0 || l.PerMinute < 0 {
		return errors.New("limits can't be negative")
	}
	return nil
}

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envVarPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	hostPattern   = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// Slug turns a name into an ID: "Acme API/v2" → "acme-api-v2".
func Slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// Project groups environments, e.g. one per app.
type Project struct {
	ID        string    `json:"id"` // slug, e.g. "my-app"
	Name      string    `json:"name"`
	Limits    Limits    `json:"limits,omitzero"`
	CreatedAt time.Time `json:"createdAt"`
}

// Environment is where tokens live and saved keys are linked: dev,
// staging, prod, or a preview per worktree.
type Environment struct {
	ID        string    `json:"id"` // "<project>/<name>", e.g. "my-app/dev"
	ProjectID string    `json:"projectId"`
	Name      string    `json:"name"`
	Limits    Limits    `json:"limits,omitzero"`
	CreatedAt time.Time `json:"createdAt"`
}

// EnvID builds an environment ID.
func EnvID(projectID, name string) string { return projectID + "/" + name }

// DefaultEnv is created on a fresh install and holds migrated stage 0 data.
const DefaultEnv = "default/dev"

// Service is a third-party API the proxy adds a real key for. Services are
// shared by every environment; each environment links its own saved key.
type Service struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category,omitempty"` // e.g. "llm", "payments"
	Docs     string   `json:"docs,omitempty"`     // the provider's API docs
	Note     string   `json:"note,omitempty"`     // a limit or gotcha worth knowing before adding it
	Hosts    []string `json:"hosts"`              // "api.openai.com" or "*.example.com"
	// The proxy token is swapped for the real key in the auth headers
	// (Authorization and Header). Header and
	// Format also say how to send the key when a request carries no proxy
	// token: Header: Format. They default to "Authorization: Bearer {key}".
	Header string `json:"header"`
	Format string `json:"format"`
	// BaseURL is the variable an SDK reads to send its calls somewhere else,
	// for quick start (no proxy, no CA): OPENAI_BASE_URL with path "/v1".
	BaseURL BaseURL `json:"baseUrl,omitzero"`
	// EnvVars get the proxy token as a placeholder: "OPENAI_API_KEY", or
	// "NAME=template" for keys with a shape, e.g. "CONVEX_DEPLOY_KEY=prod:my-app|{key}".
	// {key_compact} is the dash-free form, for CLIs that reject "-".
	EnvVars []string `json:"envVars"`
}

// BaseURL names an SDK's base-URL variable and the path it expects after
// the host ("/v1" for OpenAI, "" for Anthropic).
type BaseURL struct {
	Var  string `json:"var,omitempty"`
	Path string `json:"path,omitempty"`
}

// PrimaryHost is the host quick-start requests for this service go to: the
// first host that isn't a wildcard.
func (s Service) PrimaryHost() string {
	for _, h := range s.Hosts {
		if !strings.HasPrefix(h, "*.") {
			return strings.ToLower(h)
		}
	}
	return ""
}

// Matches reports whether host (no port) belongs to this service.
func (s Service) Matches(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range s.Hosts {
		h = strings.ToLower(h)
		if strings.HasPrefix(h, "*.") {
			if strings.HasSuffix(host, h[1:]) && len(host) > len(h)-1 {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

// Validate checks a service's settings and fills defaults.
func (s *Service) Validate() error {
	s.ID = strings.TrimSpace(strings.ToLower(s.ID))
	if s.ID == "" || len(s.Hosts) == 0 {
		return errors.New("a service needs a name and at least one host")
	}
	if !idPattern.MatchString(s.ID) {
		return errors.New("a service ID may only use a-z, 0-9, - and _")
	}
	s.Hosts = slices.Clone(s.Hosts) // may be shared, e.g. with the catalog
	for i, h := range s.Hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if !hostPattern.MatchString(h) {
			return fmt.Errorf("%q isn't a host name (letters, digits, dots and dashes, optionally starting with *.)", s.Hosts[i])
		}
		s.Hosts[i] = h
	}
	s.Header = strings.TrimSpace(s.Header)
	if s.Header == "" {
		s.Header = "Authorization"
		if s.Format == "" {
			s.Format = "Bearer {key}"
		}
	}
	if s.Format == "" {
		s.Format = "{key}"
	}
	if !strings.Contains(s.Format, "{key}") {
		return errors.New(`format must contain "{key}"`)
	}
	if s.BaseURL.Var != "" && !envVarPattern.MatchString(s.BaseURL.Var) {
		return fmt.Errorf("%q isn't a valid env var name", s.BaseURL.Var)
	}
	if s.BaseURL.Path != "" && !strings.HasPrefix(s.BaseURL.Path, "/") {
		return errors.New(`a base URL path must start with "/"`)
	}
	if s.BaseURL.Var != "" && s.PrimaryHost() == "" {
		return errors.New("a service with a base URL needs a host that isn't a wildcard")
	}
	for _, e := range s.EnvVars {
		name, tmpl, hasTmpl := strings.Cut(e, "=")
		if !envVarPattern.MatchString(name) {
			return fmt.Errorf("%q isn't a valid env var name", name)
		}
		if hasTmpl && !strings.Contains(tmpl, "{key}") && !strings.Contains(tmpl, "{key_compact}") {
			return fmt.Errorf(`%s: the template must contain "{key}" or "{key_compact}"`, name)
		}
	}
	return nil
}

// SavedKey is a real key for one service, stored once. A service can have
// several ("team", "personal"). Nothing uses a saved key directly: an
// environment links it, and its tokens get it from there.
type SavedKey struct {
	ID        string    `json:"id"`   // "key_<hex>"
	Name      string    `json:"name"` // unique among the service's saved keys
	ServiceID string    `json:"serviceId"`
	Secret    *Sealed   `json:"secret"`
	Version   int       `json:"version"` // 1 when saved, +1 each time the value is replaced
	SetAt     time.Time `json:"setAt"`   // when the value was last set
	Limits    Limits    `json:"limits,omitzero"`
	CreatedAt time.Time `json:"createdAt"`
}

// Link is the saved key an environment uses for one service. There is at
// most one per service per environment.
type Link struct {
	EnvID     string    `json:"envId"`
	ServiceID string    `json:"serviceId"`
	KeyID     string    `json:"keyId"`
	Version   int       `json:"version"` // 1 when made, +1 each time it points at another saved key
	SetAt     time.Time `json:"setAt"`
}

// Binding is a real key from before saved keys stored it: one per service per
// environment. Stores read old ones only to convert them; see FromBinding.
type Binding struct {
	EnvID     string    `json:"envId"`
	ServiceID string    `json:"serviceId"`
	Secret    *Sealed   `json:"secret"`
	SetAt     time.Time `json:"setAt"`
}

// FromBinding converts an old binding into a saved key named
// "<env> <service>" and the environment's link to it. The sealed value
// moves as it is: the master key that sealed it opens it.
func FromBinding(b Binding) (SavedKey, Link) {
	k := SavedKey{ID: NewID("key_"), Name: b.EnvID + " " + b.ServiceID, ServiceID: b.ServiceID, Secret: b.Secret,
		Version: 1, SetAt: b.SetAt, CreatedAt: b.SetAt}
	return k, Link{EnvID: b.EnvID, ServiceID: b.ServiceID, KeyID: k.ID, Version: 1, SetAt: b.SetAt}
}

// NewID returns prefix followed by 16 random hex digits.
func NewID(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand doesn't fail on supported platforms
	}
	return prefix + hex.EncodeToString(b)
}

// PrincipalRun marks the tokens EnsureToken makes (`keystub run`'s, one
// per worktree): the only ones it hands out again.
const PrincipalRun = "keystub-run"

// Token kinds. An environment token works for every service its
// environment links; a service token for one of them. Both follow the
// environment's links, so switching a link's saved key moves them too.
const (
	KindEnvironment = "environment"
	KindService     = "service"
)

// Token is what a caller holds instead of a real key. It belongs to one
// environment, which decides the real keys its requests get.
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	EnvID     string     `json:"envId"`
	Principal string     `json:"principal,omitempty"` // who it was issued to, e.g. "machine:devbox-1"
	Kind      string     `json:"kind"`                // KindEnvironment or KindService
	Service   string     `json:"service,omitempty"`   // a service token's one service
	Limits    Limits     `json:"limits,omitzero"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	TokenHash string     `json:"tokenHash"` // SHA-256 of the token, for lookup
	Token     *Sealed    `json:"token"`     // sealed token, so EnsureToken can return it
	CreatedAt time.Time  `json:"createdAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

// OldToken is a token from before saved keys stored it, with an optional list of
// services. Stores read old ones only to convert them; see Upgrade.
type OldToken struct {
	Token
	Services []string `json:"services,omitempty"`
}

// Upgrade converts an old token. No services makes an environment token
// (marked PrincipalRun if it has no principal); one service makes a
// service token for it. Several can be neither
// without widening what the token reaches, so it fails closed: the token
// is revoked (at now, if it was still live) and revoked says so.
func (o OldToken) Upgrade(now time.Time) (t Token, revoked bool) {
	t = o.Token
	if t.Kind != "" {
		return t, false
	}
	t.Kind = KindEnvironment
	switch len(o.Services) {
	case 0:
		// Before saved keys, EnsureToken handed out any token of the name, and
		// most such tokens are `keystub run`'s; marking them keeps every
		// worktree's token working.
		if t.Principal == "" {
			t.Principal = PrincipalRun
		}
	case 1:
		t.Kind, t.Service = KindService, o.Services[0]
	default:
		if t.RevokedAt == nil {
			at := now.UTC()
			t.RevokedAt = &at
			revoked = t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
		}
	}
	return t, revoked
}

// RevokedNote says which token converting revoked, and why, for whoever
// runs the server.
func (o OldToken) RevokedNote() string {
	return fmt.Sprintf("token %s (%s) in %s was revoked: it was limited to %s, and a token is now for one service or for every service its environment links; make a service token for each",
		o.Name, o.ID, o.EnvID, strings.Join(o.Services, ", "))
}

// UpgradeTokens converts old tokens and says, for whoever runs the server,
// what converting changed: each token it revoked, and the live tokens it
// marked PrincipalRun, which `keystub run` (tokens/ensure) now hands out
// again by name.
func UpgradeTokens(old []OldToken, now time.Time) (tokens []Token, notes []string) {
	var marked []string
	for _, o := range old {
		t, revoked := o.Upgrade(now)
		if revoked {
			notes = append(notes, o.RevokedNote())
		}
		if o.Kind == "" && o.Principal == "" && t.Principal == PrincipalRun && t.Usable(now) {
			marked = append(marked, fmt.Sprintf("%s (%s) in %s", t.Name, t.ID, t.EnvID))
		}
		tokens = append(tokens, t)
	}
	if len(marked) > 0 {
		notes = append(notes, "tokens "+strings.Join(marked, ", ")+" were marked as keystub run's, so `keystub run` hands each out again to a worktree of the same name; revoke any a CI job or a person uses and make it a new one")
	}
	return tokens, notes
}

// MachinePrefix starts every machine credential. It isn't a proxy token's
// prefix, so a credential is never swapped into a request or accepted as a
// token.
const MachinePrefix = "skmach_"

// Machine is a box linked with `keystub link`. Its credential lets
// `keystub run` get a token per worktree, with no admin token, in the
// environments the admin allowed when approving it. Its tokens carry
// principal "machine:<id>"; revoking the machine revokes them all.
type Machine struct {
	ID             string     `json:"id"` // "m_<hex>"
	Name           string     `json:"name"`
	Envs           []string   `json:"envs"`           // environments it may get tokens in
	CredentialHash string     `json:"credentialHash"` // SHA-256 of the credential
	CreatedAt      time.Time  `json:"createdAt"`
	LastSeen       *time.Time `json:"lastSeen,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

// Principal is what the machine's tokens record as who they were issued to.
func (m Machine) Principal() string { return "machine:" + m.ID }

// Revoked reports whether the machine was revoked.
func (m Machine) Revoked() bool { return m.RevokedAt != nil }

// Revoked reports whether the token was revoked.
func (t Token) Revoked() bool { return t.RevokedAt != nil }

// Expired reports whether the token's lifetime has passed.
func (t Token) Expired(now time.Time) bool { return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) }

// Usable reports whether the token is neither revoked nor expired.
func (t Token) Usable(now time.Time) bool { return !t.Revoked() && !t.Expired(now) }

// Allows reports whether the token may call serviceID, if its environment
// links it: a service token only its own service. Any other kind (one a
// later version wrote, say) allows nothing.
func (t Token) Allows(serviceID string) bool {
	switch t.Kind {
	case KindEnvironment:
		return true
	case KindService:
		return t.Service == serviceID
	}
	return false
}

// Entry is one proxied request, as the request log records it. It never
// holds headers, query strings or bodies, so no key can end up in it. It
// carries the project and environment, so usage adds up at any level
// without any roll-up at write time.
type Entry struct {
	Time       time.Time `json:"time"`
	Project    string    `json:"project,omitempty"`
	Env        string    `json:"env,omitempty"`
	TokenID    string    `json:"tokenId,omitempty"`
	Key        string    `json:"key"`                // token name, "" if unknown
	SavedKey   string    `json:"savedKey,omitempty"` // the saved key's ID, if one was used
	Principal  string    `json:"principal,omitempty"`
	Service    string    `json:"service"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"` // no query string
	Status     int       `json:"status"`
	DurationMs int64     `json:"durationMs"`
	OverheadMs int64     `json:"overheadMs"`     // Keystub's own time before the request went upstream
	Note       string    `json:"note,omitempty"` // why Keystub answered itself, if it did

	// What the catalog's usage metadata read from the response: numbers
	// only, never the content they came from.
	Operation  string `json:"operation,omitempty"` // e.g. "chat", from the method and path
	Model      string `json:"model,omitempty"`
	Outcome    string `json:"outcome,omitempty"` // one of the Outcome constants
	Usage      *Usage `json:"usage,omitempty"`
	CostMicros *int64 `json:"costMicros,omitempty"` // US dollars × 10⁶; nil when no price is known
	Quota      *Quota `json:"quota,omitempty"`      // what the service says is left
}

// Outcomes of a request, from the upstream status or Keystub's own answer.
const (
	OutcomeOK            = "ok"             // 1xx–3xx
	OutcomeClientError   = "client_error"   // another 4xx from the service
	OutcomeKeyRejected   = "key_rejected"   // the service refused the real key (401)
	OutcomeRateLimited   = "rate_limited"   // the service rate-limited the real key (429)
	OutcomeUpstreamError = "upstream_error" // 5xx from the service
	OutcomeUnreachable   = "unreachable"    // the service couldn't be reached
	OutcomeRefused       = "refused"        // Keystub answered itself: token, limit, no key
	OutcomeCanceled      = "canceled"       // the client went away before the service answered
)

// Usage is what one response used. Input counts every input token,
// cached and cache writes included; Cached and CacheWrite are the parts
// read from and written to the service's prompt cache. Output includes
// reasoning tokens. Units are the service's own unit when it doesn't count
// tokens (searches, characters).
type Usage struct {
	InputTokens      int64 `json:"inputTokens,omitempty"`
	CachedTokens     int64 `json:"cachedTokens,omitempty"`
	CacheWriteTokens int64 `json:"cacheWriteTokens,omitempty"`
	OutputTokens     int64 `json:"outputTokens,omitempty"`
	Units            int64 `json:"units,omitempty"`
}

// Quota is the service's own rate-limit headroom, from its response
// headers. Nil fields weren't sent.
type Quota struct {
	RequestsLeft *int64 `json:"requestsLeft,omitempty"`
	TokensLeft   *int64 `json:"tokensLeft,omitempty"`
}
