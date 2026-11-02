package dashboard

// The JSON API under /api: the routes protocol/api.md describes, as the
// self-hosted server provides them. Callers send the admin API key as a
// bearer token (or are a signed-in dashboard page). Errors are
// {"error": {"type": "keystub", "message": "…"}}.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

// maxAPIBody caps a request body: room for a 64 KiB key and its JSON.
const maxAPIBody = 256 << 10

func (s *Server) routeAPI(m *http.ServeMux, a func(http.HandlerFunc) http.Handler) {
	m.Handle("GET /api/me", a(s.apiMe))
	m.Handle("GET /api/projects", a(s.apiProjects))
	m.Handle("POST /api/projects", a(s.apiAddProject))
	m.Handle("GET /api/environments", a(s.apiEnvironments))
	m.Handle("POST /api/environments", a(s.apiAddEnvironment))
	m.Handle("/api/environments/", a(s.apiEnvironment)) // {env} holds a slash; see envPath
	m.Handle("GET /api/catalog", a(s.apiCatalog))
	m.Handle("GET /api/services", a(s.apiServices))
	m.Handle("POST /api/services", a(s.apiAddService))
	m.Handle("PATCH /api/services/{id}", a(s.apiUpdateService))
	m.Handle("DELETE /api/services/{id}", a(s.apiRemoveService))
	m.Handle("GET /api/keys", a(s.apiKeys))
	m.Handle("POST /api/keys", a(s.apiAddKey))
	m.Handle("GET /api/keys/{id}", a(s.apiKey))
	m.Handle("PATCH /api/keys/{id}", a(s.apiUpdateKey))
	m.Handle("PUT /api/keys/{id}/value", a(s.apiReplaceKey))
	m.Handle("DELETE /api/keys/{id}", a(s.apiDeleteKey))
	m.Handle("POST /api/tokens/{id}/revoke", a(s.apiRevokeToken))
	m.Handle("POST /api/tokens/ensure", a(s.apiEnsure))
	m.Handle("GET /api/usage", a(s.apiUsage))
	m.Handle("GET /api/ca.pem", a(s.apiCA))
	// Hosted signs the CLI in with a code; this server doesn't. These answer
	// without a key, as on hosted, so the CLI can say to use an API key.
	noLogin := func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "this server doesn't sign the CLI in with a code: use its admin API key (admin.token) as KEYSTUB_API_KEY")
	}
	m.HandleFunc("POST /api/cli/login", noLogin)
	m.HandleFunc("POST /api/cli/login/poll", noLogin)
	m.Handle("/api/", a(func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "no such API route")
	}))
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// APIError is the body of every error the API returns.
type APIError struct {
	Error struct {
		Type     string   `json:"type"`
		Message  string   `json:"message"`
		LinkedIn []string `json:"linkedIn,omitempty"` // a saved key that is still linked
	} `json:"error"`
}

func apiError(w http.ResponseWriter, status int, msg string) {
	var e APIError
	e.Error.Type, e.Error.Message = "keystub", msg
	writeJSON(w, status, e)
}

// fail answers with the status an engine error calls for: 404 for
// something missing, 409 for a clash with what exists, 400 otherwise.
func fail(w http.ResponseWriter, err error) {
	var inUse *core.KeyInUseError
	switch {
	case errors.As(err, &inUse):
		var e APIError
		e.Error.Type, e.Error.Message, e.Error.LinkedIn = "keystub", err.Error(), inUse.Envs
		writeJSON(w, http.StatusConflict, e)
	case errors.Is(err, core.ErrNotFound):
		apiError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, core.ErrNameTaken), errors.Is(err, core.ErrNotLinked), errors.Is(err, core.ErrKeyInUse):
		apiError(w, http.StatusConflict, err.Error())
	default:
		apiError(w, http.StatusBadRequest, err.Error())
	}
}

// decode reads a JSON object body into v. An empty body leaves v as it is.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength != 0 && !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "send a JSON body with Content-Type: application/json")
		return false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAPIBody))
	if err != nil {
		apiError(w, http.StatusRequestEntityTooLarge, "body is too large")
		return false
	}
	if strings.TrimSpace(string(b)) == "" {
		return true
	}
	if b = []byte(strings.TrimSpace(string(b))); b[0] != '{' {
		apiError(w, http.StatusBadRequest, "body must be a JSON object")
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		apiError(w, http.StatusBadRequest, "body isn't valid: "+err.Error())
		return false
	}
	return true
}

// Limits is a limit object as the API sends it: both fields, always.
type Limits struct {
	DailyRequests int `json:"dailyRequests"`
	PerMinute     int `json:"perMinute"`
}

func apiLimits(l core.Limits) Limits {
	return Limits{DailyRequests: l.DailyRequests, PerMinute: l.PerMinute}
}

func (l *Limits) core() core.Limits {
	if l == nil {
		return core.Limits{}
	}
	return core.Limits{DailyRequests: l.DailyRequests, PerMinute: l.PerMinute}
}

// --- account, projects, environments ---

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"server":  "self-hosted",
		"account": map[string]string{"id": "local", "name": "This server"},
		"apiKey":  map[string]any{"id": "admin", "envs": nil},
		"notices": append([]string{}, s.Notices...),
	})
}

// Project is a project as the API sends it.
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Limits    Limits    `json:"limits"`
	CreatedAt time.Time `json:"createdAt"`
}

// Environment is an environment as the API sends it.
type Environment struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	Name      string    `json:"name"`
	Limits    Limits    `json:"limits"`
	CreatedAt time.Time `json:"createdAt"`
}

func apiEnv(e core.Environment) Environment {
	return Environment{ID: e.ID, ProjectID: e.ProjectID, Name: e.Name, Limits: apiLimits(e.Limits), CreatedAt: e.CreatedAt}
}

func (s *Server) apiProjects(w http.ResponseWriter, r *http.Request) {
	out := []Project{}
	for _, p := range s.Core.Projects() {
		out = append(out, Project{ID: p.ID, Name: p.Name, Limits: apiLimits(p.Limits), CreatedAt: p.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

func (s *Server) apiAddProject(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string  `json:"name"`
		Limits *Limits `json:"limits"`
	}
	if !decode(w, r, &in) {
		return
	}
	p, err := s.Core.AddProject(r.Context(), in.Name, in.Limits.core())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"project": Project{ID: p.ID, Name: p.Name, Limits: apiLimits(p.Limits), CreatedAt: p.CreatedAt}})
}

func (s *Server) apiEnvironments(w http.ResponseWriter, r *http.Request) {
	out := []Environment{}
	for _, e := range s.Core.Environments() {
		out = append(out, apiEnv(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"environments": out})
}

func (s *Server) apiAddEnvironment(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Project string  `json:"project"`
		Name    string  `json:"name"`
		Limits  *Limits `json:"limits"`
	}
	if !decode(w, r, &in) {
		return
	}
	e, err := s.Core.AddEnvironment(r.Context(), in.Project, in.Name, in.Limits.core())
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"environment": apiEnv(e)})
}

// envPath splits /api/environments/<env>/<rest…>. The environment is
// "<project>/<env>", sent with its slash as is or as %2F.
func envPath(r *http.Request) (env string, rest []string) {
	seg := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/api/environments/"), "/")
	for i, v := range seg {
		u, err := url.PathUnescape(v)
		if err != nil {
			u = "\x00" // matches no environment or route
		}
		seg[i] = u
	}
	if strings.Contains(seg[0], "/") || len(seg) < 2 {
		return seg[0], seg[1:]
	}
	return seg[0] + "/" + seg[1], seg[2:]
}

// apiEnvironment serves everything under one environment.
func (s *Server) apiEnvironment(w http.ResponseWriter, r *http.Request) {
	id, rest := envPath(r)
	if len(rest) > 0 && rest[len(rest)-1] == "" { // a trailing slash
		rest = rest[:len(rest)-1]
	}
	env, ok := s.Core.Environment(id)
	if !ok {
		apiError(w, http.StatusNotFound, "no environment "+id)
		return
	}
	route := r.Method + " " + strings.Join(append([]string{""}, rest...), "/")
	switch {
	case route == "PATCH ":
		s.apiEnvLimits(w, r, env)
	case route == "DELETE ":
		if err := s.Core.DeleteEnvironment(r.Context(), env.ID); err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case route == "GET /links":
		s.apiLinks(w, r, env)
	case len(rest) == 2 && rest[0] == "links" && r.Method == http.MethodPut:
		s.apiLink(w, r, env, rest[1])
	case len(rest) == 2 && rest[0] == "links" && r.Method == http.MethodDelete:
		if err := s.Core.Unlink(r.Context(), env.ID, rest[1]); err != nil {
			fail(w, fmt.Errorf("%s isn't linked in %s: %w", rest[1], env.ID, err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case route == "GET /tokens":
		s.apiTokens(w, r, env)
	case route == "POST /tokens":
		s.apiCreateToken(w, r, env)
	case route == "GET /setup":
		s.apiSetup(w, r, env)
	case slices.Contains([]string{"", "links", "tokens", "setup"}, strings.Join(rest, "/")),
		len(rest) == 2 && rest[0] == "links":
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		apiError(w, http.StatusNotFound, "no such API route")
	}
}

func (s *Server) apiEnvLimits(w http.ResponseWriter, r *http.Request, env core.Environment) {
	var in struct {
		Limits json.RawMessage `json:"limits"` // null clears them; it can't be left out
	}
	if !decode(w, r, &in) {
		return
	}
	var l *Limits
	if len(in.Limits) == 0 || json.Unmarshal(in.Limits, &l) != nil {
		apiError(w, http.StatusBadRequest, `body must be {"limits": {"dailyRequests": n, "perMinute": n}}, or {"limits": null} to clear them`)
		return
	}
	if err := s.Core.SetEnvironmentLimits(r.Context(), env.ID, l.core()); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- services ---

func (s *Server) apiCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"services": catalog.Presets})
}

func (s *Server) apiServices(w http.ResponseWriter, r *http.Request) {
	out := s.Core.Services()
	if out == nil {
		out = []core.Service{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (s *Server) apiAddService(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Catalog *string  `json:"catalog"`
		Name    string   `json:"name"`
		Hosts   []string `json:"hosts"`
		Header  string   `json:"header"`
		Format  string   `json:"format"`
		EnvVars []string `json:"envVars"`
	}
	if !decode(w, r, &in) {
		return
	}
	var svc core.Service
	if in.Catalog != nil {
		p, ok := catalog.Preset(*in.Catalog)
		if !ok {
			apiError(w, http.StatusNotFound, "no service "+*in.Catalog+" in the catalog")
			return
		}
		svc = p
	} else {
		name := strings.TrimSpace(in.Name)
		svc = core.Service{ID: core.Slug(name), Name: name, Hosts: in.Hosts, Header: in.Header, Format: in.Format, EnvVars: in.EnvVars}
		if err := checkCustom(svc); err != nil {
			fail(w, err)
			return
		}
	}
	if err := s.Core.AddService(r.Context(), svc); err != nil {
		fail(w, err)
		return
	}
	id := strings.ToLower(strings.TrimSpace(svc.ID))
	for _, x := range s.Core.Services() {
		if x.ID == id {
			writeJSON(w, http.StatusCreated, map[string]any{"service": x})
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"service": svc})
}

// checkCustom refuses a custom service that would take a catalog
// service's ID: the catalog's hosts are the ones that service's keys go to.
func checkCustom(svc core.Service) error {
	if _, ok := catalog.Preset(core.Slug(svc.ID)); ok {
		return fmt.Errorf("%q is a catalog service: add it from the catalog, or give a custom one another name: %w", core.Slug(svc.ID), core.ErrNameTaken)
	}
	return nil
}

// apiUpdateService changes a custom service. Catalog services can't be
// changed, and a service that saved keys are for can't either (409).
func (s *Server) apiUpdateService(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var cur core.Service
	found := false
	for _, x := range s.Core.Services() {
		if x.ID == id {
			cur, found = x, true
		}
	}
	if !found {
		apiError(w, http.StatusNotFound, "no service "+id)
		return
	}
	if _, ok := catalog.Preset(id); ok {
		apiError(w, http.StatusConflict, id+" is a catalog service; it can't be changed")
		return
	}
	var in struct {
		Name    *string  `json:"name"`
		Hosts   []string `json:"hosts"`
		Header  *string  `json:"header"`
		Format  *string  `json:"format"`
		EnvVars []string `json:"envVars"`
	}
	if !decode(w, r, &in) {
		return
	}
	svc := cur
	svc.Hosts, svc.EnvVars = slices.Clone(cur.Hosts), slices.Clone(cur.EnvVars)
	if in.Name != nil {
		if svc.Name = strings.TrimSpace(*in.Name); svc.Name == "" {
			apiError(w, http.StatusBadRequest, "a service needs a name")
			return
		}
	}
	if in.Hosts != nil {
		svc.Hosts = in.Hosts
	}
	if in.Header != nil {
		svc.Header = *in.Header
	}
	if in.Format != nil {
		svc.Format = *in.Format
	}
	if in.EnvVars != nil {
		svc.EnvVars = in.EnvVars
	}
	if err := s.Core.UpdateService(r.Context(), svc); err != nil {
		fail(w, err)
		return
	}
	for _, x := range s.Core.Services() {
		if x.ID == id {
			svc = x
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": svc})
}

func (s *Server) apiRemoveService(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.RemoveService(r.Context(), r.PathValue("id")); err != nil {
		fail(w, fmt.Errorf("service %s: %w", r.PathValue("id"), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- saved keys ---

// Key is a saved key as the API sends it: never its value.
type Key struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Service  string    `json:"service"`
	Version  int       `json:"version"`
	SetAt    time.Time `json:"setAt"`
	Limits   *Limits   `json:"limits"` // null when it has none
	LinkedIn []string  `json:"linkedIn"`
}

func (s *Server) apiKeyOf(k core.SavedKey) Key {
	out := Key{ID: k.ID, Name: k.Name, Service: k.ServiceID, Version: k.Version, SetAt: k.SetAt, LinkedIn: s.Core.KeyLinkedIn(k.ID)}
	if k.Limits != (core.Limits{}) {
		l := apiLimits(k.Limits)
		out.Limits = &l
	}
	return out
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request) {
	out := []Key{}
	for _, k := range s.Core.Keys() {
		out = append(out, s.apiKeyOf(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) apiAddKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Service string  `json:"service"`
		Name    string  `json:"name"`
		Value   string  `json:"value"`
		Limits  *Limits `json:"limits"`
	}
	if !decode(w, r, &in) {
		return
	}
	k, err := s.Core.AddKey(r.Context(), core.KeySpec{ServiceID: in.Service, Name: in.Name, Value: in.Value, Limits: in.Limits.core()})
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"key": s.apiKeyOf(k)})
}

func (s *Server) apiKey(w http.ResponseWriter, r *http.Request) {
	k, ok := s.Core.Key(r.PathValue("id"))
	if !ok {
		apiError(w, http.StatusNotFound, "no saved key "+r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": s.apiKeyOf(k)})
}

func (s *Server) apiUpdateKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   *string         `json:"name"`
		Limits json.RawMessage `json:"limits"` // null clears them; absent leaves them
	}
	if !decode(w, r, &in) {
		return
	}
	c := core.KeyChange{Name: in.Name}
	if len(in.Limits) > 0 {
		var l *Limits
		if err := json.Unmarshal(in.Limits, &l); err != nil {
			apiError(w, http.StatusBadRequest, "limits must be {\"dailyRequests\": n, \"perMinute\": n} or null")
			return
		}
		cl := l.core()
		c.Limits = &cl
	}
	k, err := s.Core.UpdateKey(r.Context(), r.PathValue("id"), c)
	if err != nil {
		fail(w, fmt.Errorf("saved key %s: %w", r.PathValue("id"), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": s.apiKeyOf(k)})
}

func (s *Server) apiReplaceKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Value string `json:"value"`
	}
	if !decode(w, r, &in) {
		return
	}
	k, err := s.Core.ReplaceKey(r.Context(), r.PathValue("id"), in.Value)
	if err != nil {
		fail(w, fmt.Errorf("saved key %s: %w", r.PathValue("id"), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": s.apiKeyOf(k)})
}

func (s *Server) apiDeleteKey(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.DeleteKey(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, core.ErrNotFound) {
			err = fmt.Errorf("saved key %s: %w", r.PathValue("id"), err)
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- links ---

// Link is a link as the API sends it.
type Link struct {
	Env     string    `json:"env"`
	Service string    `json:"service"`
	Key     KeyRef    `json:"key"`
	Version int       `json:"version"`
	SetAt   time.Time `json:"setAt"`
}

// KeyRef names a saved key.
type KeyRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Server) apiLinkOf(l core.Link) Link {
	k, _ := s.Core.Key(l.KeyID)
	return Link{Env: l.EnvID, Service: l.ServiceID, Key: KeyRef{ID: l.KeyID, Name: k.Name}, Version: l.Version, SetAt: l.SetAt}
}

func (s *Server) apiLinks(w http.ResponseWriter, r *http.Request, env core.Environment) {
	out := []Link{}
	for _, l := range s.Core.Links(env.ID) {
		out = append(out, s.apiLinkOf(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

func (s *Server) apiLink(w http.ResponseWriter, r *http.Request, env core.Environment, service string) {
	var in struct {
		Key          string `json:"key"`
		ServiceToken *bool  `json:"serviceToken"`
		TokenName    string `json:"tokenName"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Key == "" {
		apiError(w, http.StatusBadRequest, `body must name the saved key: {"key": "key_…"}`)
		return
	}
	res, err := s.Core.LinkKey(r.Context(), core.LinkSpec{EnvID: env.ID, ServiceID: service, KeyID: in.Key,
		ServiceToken: in.ServiceToken == nil || *in.ServiceToken, TokenName: in.TokenName})
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"link": s.apiLinkOf(res.Link)}
	if res.Token != nil {
		out["token"] = newToken(res.Secret, *res.Token, s.Core.TokenState(res.Token.ID))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- tokens ---

// Token is a proxy token as the API sends it: never its value, but for a
// new one (NewToken).
type Token struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Env       string     `json:"env"`
	Kind      string     `json:"kind"`
	Service   *string    `json:"service"`
	Principal *string    `json:"principal"`
	Limits    Limits     `json:"limits"`
	ExpiresAt *time.Time `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt"`
	CreatedAt time.Time  `json:"createdAt"`
	State     string     `json:"state"` // active, revoked or expired
}

// NewToken is a token just made: shown once.
type NewToken struct {
	Token
	Secret string `json:"token"`
}

func apiToken(t core.Token, state string) Token {
	out := Token{ID: t.ID, Name: t.Name, Env: t.EnvID, Kind: t.Kind, Limits: apiLimits(t.Limits),
		ExpiresAt: t.ExpiresAt, RevokedAt: t.RevokedAt, CreatedAt: t.CreatedAt, State: state}
	if out.Kind == "" {
		out.Kind = "unknown" // allows nothing; see core.Token.Allows
	}
	if t.Service != "" {
		out.Service = &t.Service
	}
	if t.Principal != "" {
		out.Principal = &t.Principal
	}
	return out
}

func newToken(secret string, t core.Token, state string) NewToken {
	return NewToken{Token: apiToken(t, state), Secret: secret}
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, env core.Environment) {
	out := []Token{}
	for _, t := range s.Core.Tokens(env.ID) {
		out = append(out, apiToken(t, s.Core.TokenState(t.ID)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Server) apiCreateToken(w http.ResponseWriter, r *http.Request, env core.Environment) {
	var in struct {
		Name    string  `json:"name"`
		TTL     string  `json:"ttl"`
		Limits  *Limits `json:"limits"`
		Service *string `json:"service"`
	}
	if !decode(w, r, &in) {
		return
	}
	ttl, err := parseTTL(in.TTL)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	spec := core.TokenSpec{EnvID: env.ID, Name: in.Name, Limits: in.Limits.core(), TTL: ttl}
	if in.Service != nil {
		if *in.Service == "" {
			apiError(w, http.StatusBadRequest, "service can't be empty: leave it out (or null) for an environment token")
			return
		}
		spec.Service = *in.Service
	}
	secret, t, err := s.Core.CreateToken(r.Context(), spec)
	if err != nil {
		if errors.Is(err, core.ErrNameTaken) {
			err = fmt.Errorf("a live token in %s is already named %q: %w", env.ID, strings.TrimSpace(in.Name), err)
		}
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": newToken(secret, t, s.Core.TokenState(t.ID))})
}

func (s *Server) apiRevokeToken(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.RevokeToken(r.Context(), r.PathValue("id")); err != nil {
		fail(w, fmt.Errorf("token %s: %w", r.PathValue("id"), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// TokenResponse is what POST /api/tokens/ensure returns: `keystub run`'s
// token for a worktree.
type TokenResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Env       string     `json:"env"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Token     string     `json:"token"`
}

func (s *Server) apiEnsure(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Env  string `json:"env"`
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		apiError(w, http.StatusBadRequest, `body must be {"env": "project/env", "name": "…"}`)
		return
	}
	if in.Env == "" {
		in.Env = core.DefaultEnv
	}
	if _, ok := s.Core.Environment(in.Env); !ok {
		apiError(w, http.StatusNotFound, "no environment "+in.Env)
		return
	}
	secret, t, err := s.Core.EnsureToken(r.Context(), in.Env, in.Name)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, TokenResponse{ID: t.ID, Name: t.Name, Env: t.EnvID, ExpiresAt: t.ExpiresAt, Token: secret})
}

// --- usage, setup, CA ---

func (s *Server) apiUsage(w http.ResponseWriter, r *http.Request) {
	mr := s.metrics()
	if mr == nil {
		apiError(w, http.StatusNotFound, "this storage keeps no usage metrics")
		return
	}
	if rng := r.FormValue("range"); rng != "" {
		if _, ok := usageRanges[rng]; !ok {
			apiError(w, http.StatusBadRequest, "range must be 24h, 7d or 30d")
			return
		}
	}
	for _, b := range strings.Split(r.FormValue("by"), ",") {
		if b != "" && !slices.Contains(usage.Dimensions, b) {
			apiError(w, http.StatusBadRequest, "by takes "+strings.Join(usage.Dimensions, ", "))
			return
		}
	}
	q, _ := s.usageQuery(r, []string{"service"})
	rows, err := mr.Metrics(r.Context(), q)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "couldn't read usage")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": usage.Export(rows, s.tokenNames())})
}

// Setup is how a box uses an environment: the quick-start lines for the
// services it links. The self-hosted server has no hosted remote proxy.
type Setup struct {
	EdgeURL          string   `json:"edgeUrl"`
	GatewayURL       *string  `json:"gatewayUrl"`
	EnvLines         []string `json:"envLines"`
	RemoteProxyLines []string `json:"remoteProxyLines"`
}

func (s *Server) apiSetup(w http.ResponseWriter, r *http.Request, env core.Environment) {
	out := Setup{EnvLines: []string{}}
	if s.EdgeAddr != "" {
		out.EdgeURL = "http://" + s.EdgeAddr
	}
	for _, l := range s.Core.LinkStatuses(env.ID) {
		if !l.Linked {
			continue
		}
		svc := l.Service
		if svc.BaseURL.Var != "" && out.EdgeURL != "" {
			out.EnvLines = append(out.EnvLines, svc.BaseURL.Var+"="+out.EdgeURL+"/s/"+svc.ID+svc.BaseURL.Path)
		}
		for _, v := range svc.EnvVars {
			name, tmpl, ok := strings.Cut(v, "=")
			if !ok {
				tmpl = "{key}"
			}
			val := strings.NewReplacer("{key}", "<token>", "{key_compact}", "<token>").Replace(tmpl)
			out.EnvLines = append(out.EnvLines, name+"="+val)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiCA(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(s.CAPath)
	if s.CAPath == "" || err != nil {
		apiError(w, http.StatusNotFound, "this server has no CA certificate")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="keystub-ca.pem"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
