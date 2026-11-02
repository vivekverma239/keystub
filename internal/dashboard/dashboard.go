// Package dashboard is Keystub's local admin page: projects and
// environments, saved keys and the key each environment links per service,
// proxy tokens, and the request log. It also serves the JSON API under
// /api (see protocol/api.md) that `keystub run` and the CLI use. Pages and
// API calls need the admin token.
package dashboard

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vivekverma239/keystub/catalog"
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/usage"
)

// ControlPlane is what the dashboard needs from the core. *core.Engine
// provides it; a hosted portal would be another client of the same methods.
type ControlPlane interface {
	Projects() []core.Project
	AddProject(ctx context.Context, name string, limits core.Limits) (core.Project, error)
	SetProjectLimits(ctx context.Context, id string, limits core.Limits) error
	Environments() []core.Environment
	Environment(id string) (core.Environment, bool)
	AddEnvironment(ctx context.Context, projectID, name string, limits core.Limits) (core.Environment, error)
	SetEnvironmentLimits(ctx context.Context, id string, limits core.Limits) error
	DeleteEnvironment(ctx context.Context, id string) error

	Services() []core.Service
	AddService(ctx context.Context, s core.Service) error
	UpdateService(ctx context.Context, s core.Service) error
	RemoveService(ctx context.Context, id string) error

	Keys() []core.SavedKey
	Key(id string) (core.SavedKey, bool)
	KeyLinkedIn(id string) []string
	AddKey(ctx context.Context, spec core.KeySpec) (core.SavedKey, error)
	ReplaceKey(ctx context.Context, id, value string) (core.SavedKey, error)
	UpdateKey(ctx context.Context, id string, c core.KeyChange) (core.SavedKey, error)
	DeleteKey(ctx context.Context, id string) error

	Links(envID string) []core.Link
	LinkStatuses(envID string) []core.LinkStatus
	LinkKey(ctx context.Context, spec core.LinkSpec) (core.LinkResult, error)
	Unlink(ctx context.Context, envID, serviceID string) error

	Tokens(envID string) []core.Token
	CreateToken(ctx context.Context, spec core.TokenSpec) (string, core.Token, error)
	EnsureToken(ctx context.Context, envID, name string) (string, core.Token, error)
	RevokeToken(ctx context.Context, id string) error
	TokenState(id string) string
	UsedToday(ctx context.Context, key string) int

	PendingLinks() []core.LinkRequest
	PendingLink(code string) (core.LinkRequest, error)
	ApproveLink(ctx context.Context, code string, envs []string) (core.Machine, error)
	DenyLink(code string) error
	DenyLinkRequest(id string) error
	Machines() []core.Machine
	RevokeMachine(ctx context.Context, id string) error
}

//go:embed templates/*.html
var files embed.FS

const cookieName = "keystub_session"

// Server is the dashboard's http.Handler.
type Server struct {
	Core       ControlPlane
	Log        core.LogReader
	Metrics    usage.Reader // hourly usage; nil means Log's, if it keeps them
	SecretsIn  string       // where the master key lives, e.g. "macOS Keychain"
	Token      string       // admin token
	ProxyAddr  string
	EdgeAddr   string // where /s and /h are served, for quick start
	CAPath     string
	BundlePath string
	Notices    []string // what converting older data changed, shown on every page

	pages map[string]*template.Template
	mux   *http.ServeMux
	csrf  *http.CrossOriginProtection
}

// New wires up the routes.
func New(s *Server) (*Server, error) {
	funcs := template.FuncMap{
		"date":  func(t time.Time) string { return t.Local().Format("2 Jan 2006") },
		"clock": func(t time.Time) string { return t.Local().Format("15:04:05") },
		"when": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.Local().Format("2 Jan 15:04")
		},
		"join":   strings.Join,
		"limits": limitsText,
		"num":    formatInt,
		"usd":    formatUSD,
		"pct":    percent,
		"micros": func(p *int64) string {
			if p == nil {
				return ""
			}
			return formatUSD(float64(*p) / 1e6)
		},
		"statusPage": usage.StatusPage,
	}
	s.csrf = http.NewCrossOriginProtection()
	s.pages = map[string]*template.Template{}
	for _, name := range []string{"services", "keys", "tokens", "projects", "machines", "requests", "usage", "setup", "login"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(files, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		s.pages[name] = t
	}

	m := http.NewServeMux()
	a := func(h http.HandlerFunc) http.Handler { return s.auth(h) }
	m.HandleFunc("GET /login", s.login)
	m.Handle("GET /{$}", a(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/services", http.StatusSeeOther) }))
	m.Handle("GET /services", a(s.services))
	m.Handle("POST /services/preset", a(s.addPreset))
	m.Handle("POST /services/custom", a(s.addCustom))
	m.Handle("POST /services/{id}/key", a(s.newKeyAndLink))
	m.Handle("POST /services/{id}/link", a(s.linkKey))
	m.Handle("POST /services/{id}/unlink", a(s.unlinkKey))
	m.Handle("POST /services/{id}/remove", a(s.removeService))
	m.Handle("GET /keys", a(s.keys))
	m.Handle("POST /keys", a(s.addKey))
	m.Handle("POST /keys/{id}/replace", a(s.replaceKey))
	m.Handle("POST /keys/{id}/rename", a(s.renameKey))
	m.Handle("POST /keys/{id}/limits", a(s.keyLimits))
	m.Handle("POST /keys/{id}/delete", a(s.deleteKey))
	m.Handle("GET /tokens", a(s.tokens))
	m.Handle("POST /tokens", a(s.createToken))
	m.Handle("POST /tokens/{id}/revoke", a(s.revokeToken))
	m.Handle("GET /projects", a(s.projects))
	m.Handle("POST /projects", a(s.addProject))
	m.Handle("POST /projects/{id}/limits", a(s.projectLimits))
	m.Handle("POST /environments", a(s.addEnvironment))
	m.Handle("POST /environments/limits", a(s.envLimits))
	m.Handle("POST /environments/delete", a(s.deleteEnvironment))
	m.Handle("GET /machines", a(s.machines))
	m.Handle("POST /machines/check", a(s.checkMachine))
	m.Handle("POST /machines/approve", a(s.approveMachine))
	m.Handle("POST /machines/{id}/revoke", a(s.revokeMachine))
	m.Handle("POST /machines/pending/{id}/deny", a(s.denyMachine))
	m.Handle("GET /requests", a(s.requests))
	m.Handle("GET /usage", a(s.usagePage))
	m.Handle("GET /usage/export", a(s.usageExport))
	m.Handle("GET /metrics", a(s.prometheus))
	m.Handle("GET /setup", a(s.setup))
	s.routeAPI(m, a)
	s.mux = m
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
	w.Header().Set("Referrer-Policy", "same-origin")
	s.mux.ServeHTTP(w, r)
}

// --- auth ---

func (s *Server) validToken(t string) bool {
	return t != "" && subtle.ConstantTimeCompare([]byte(t), []byte(s.Token)) == 1
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok := false
		if c, err := r.Cookie(cookieName); err == nil && s.validToken(c.Value) {
			ok = true
		}
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") && s.validToken(strings.TrimPrefix(h, "Bearer ")) {
			ok = true
		}
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				apiError(w, http.StatusUnauthorized, "no valid admin API key: send Authorization: Bearer <the key in admin.token>")
				return
			}
			s.renderStatus(w, http.StatusUnauthorized, "login", "Sign in", "", nil)
			return
		}
		// Forms must come from this dashboard, not another site. Requests
		// with no browser headers (keystub run) pass.
		if err := s.csrf.Check(r); err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				apiError(w, http.StatusForbidden, "cross-site request refused")
				return
			}
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r.URL.Query().Get("token")) {
		s.renderStatus(w, http.StatusUnauthorized, "login", "Sign in", "", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.Token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}

// --- rendering ---

type page struct {
	Title   string
	Active  string
	Error   string
	Env     core.Environment   // the environment the page is about
	Envs    []core.Environment // for the switcher
	Data    any
	Notices []string
}

func (s *Server) renderStatus(w http.ResponseWriter, status int, name, title, errMsg string, data any, env ...core.Environment) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	p := page{Title: title, Active: name, Error: errMsg, Data: data, Notices: s.Notices}
	if len(env) > 0 {
		p.Env, p.Envs = env[0], s.Core.Environments()
	}
	_ = s.pages[name].ExecuteTemplate(w, "layout.html", p)
}

// env picks the environment from ?env= (or a form field), else the default,
// else the first one. An env that is named but doesn't exist is returned
// by ID only, so writes to it fail instead of landing somewhere else.
func (s *Server) env(r *http.Request) core.Environment {
	if id := r.FormValue("env"); id != "" {
		if v, ok := s.Core.Environment(id); ok {
			return v
		}
		return core.Environment{ID: id}
	}
	if v, ok := s.Core.Environment(core.DefaultEnv); ok {
		return v
	}
	if all := s.Core.Environments(); len(all) > 0 {
		return all[0]
	}
	return core.Environment{}
}

func back(w http.ResponseWriter, r *http.Request, path string, env core.Environment) {
	http.Redirect(w, r, path+"?env="+url.QueryEscape(env.ID), http.StatusSeeOther)
}

func limitsText(l core.Limits) string {
	var parts []string
	if l.DailyRequests > 0 {
		parts = append(parts, fmt.Sprintf("%d/day", l.DailyRequests))
	}
	if l.PerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d/min", l.PerMinute))
	}
	if len(parts) == 0 {
		return "None"
	}
	return strings.Join(parts, ", ")
}

func formLimits(r *http.Request) (core.Limits, error) {
	num := func(field string) (int, error) {
		v := strings.TrimSpace(r.FormValue(field))
		if v == "" {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%s must be a whole number", field)
		}
		return n, nil
	}
	d, err := num("dailyRequests")
	if err != nil {
		return core.Limits{}, errors.New("daily limit must be a whole number")
	}
	m, err := num("perMinute")
	if err != nil {
		return core.Limits{}, errors.New("per-minute limit must be a whole number")
	}
	return core.Limits{DailyRequests: d, PerMinute: m}, nil
}

// maxTTL is the longest lifetime a token can be given; leave it empty for
// no expiry.
const maxTTL = 10 * 365 * 24 * time.Hour

// parseTTL reads "90m", "2h" or "7d"; "" means no expiry.
func parseTTL(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, errors.New("lifetime must look like 30m, 2h or 7d")
		}
		if n > int(maxTTL/(24*time.Hour)) {
			return 0, errors.New("lifetime can be at most 10 years; leave it empty for no expiry")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, errors.New("lifetime must look like 30m, 2h or 7d")
	}
	if d > maxTTL {
		return 0, errors.New("lifetime can be at most 10 years; leave it empty for no expiry")
	}
	return d, nil
}

// --- services and real keys ---

type servicesData struct {
	Links   []linkRow
	Presets []presetGroup
}

// linkRow is a service on the environment page: what the environment
// links for it, and the saved keys it could link instead.
type linkRow struct {
	core.LinkStatus
	Choices []core.SavedKey
}

// presetGroup is the catalog services of one category not added yet.
type presetGroup struct {
	Category string
	Services []core.Service
}

// categoryNames orders and names the catalog's categories; any other
// category is shown after these under its own name.
var categoryNames = []struct{ id, name string }{
	{"llm", "AI models"}, {"speech", "Speech"}, {"code", "Code"}, {"infrastructure", "Infrastructure"},
	{"database", "Databases"}, {"payments", "Payments"}, {"email", "Email"}, {"messaging", "Messaging"},
	{"productivity", "Productivity"}, {"search", "Search"}, {"observability", "Observability"},
}

func (s *Server) servicesData(env core.Environment) servicesData {
	byService := map[string][]core.SavedKey{}
	for _, k := range s.Core.Keys() {
		byService[k.ServiceID] = append(byService[k.ServiceID], k)
	}
	var links []linkRow
	have := map[string]bool{}
	for _, l := range s.Core.LinkStatuses(env.ID) {
		have[l.Service.ID] = true
		links = append(links, linkRow{LinkStatus: l, Choices: byService[l.Service.ID]})
	}
	byCat := map[string][]core.Service{}
	var order []string
	for _, p := range catalog.Presets {
		if have[p.ID] {
			continue
		}
		if _, ok := byCat[p.Category]; !ok {
			order = append(order, p.Category)
		}
		byCat[p.Category] = append(byCat[p.Category], p)
	}
	var groups []presetGroup
	for _, c := range categoryNames {
		if svcs := byCat[c.id]; len(svcs) > 0 {
			groups = append(groups, presetGroup{Category: c.name, Services: svcs})
			delete(byCat, c.id)
		}
	}
	for _, c := range order {
		if svcs := byCat[c]; len(svcs) > 0 {
			name := c
			if name == "" {
				name = "Other"
			}
			groups = append(groups, presetGroup{Category: name, Services: svcs})
		}
	}
	return servicesData{Links: links, Presets: groups}
}

func (s *Server) services(w http.ResponseWriter, r *http.Request) {
	env := s.env(r)
	s.renderStatus(w, http.StatusOK, "services", "Services", "", s.servicesData(env), env)
}

func (s *Server) servicesError(w http.ResponseWriter, r *http.Request, err error) {
	env := s.env(r)
	s.renderStatus(w, http.StatusBadRequest, "services", "Services", err.Error(), s.servicesData(env), env)
}

func (s *Server) addPreset(w http.ResponseWriter, r *http.Request) {
	p, ok := catalog.Preset(r.FormValue("id"))
	if !ok {
		s.servicesError(w, r, errors.New("unknown preset"))
		return
	}
	if err := s.Core.AddService(r.Context(), p); err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", s.env(r))
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) addCustom(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	svc := core.Service{
		ID: core.Slug(name), Name: name,
		Hosts:   splitList(r.FormValue("hosts")),
		Header:  strings.TrimSpace(r.FormValue("header")),
		Format:  strings.TrimSpace(r.FormValue("format")),
		EnvVars: splitList(r.FormValue("envVars")),
	}
	err := checkCustom(svc)
	if err == nil {
		err = s.Core.AddService(r.Context(), svc)
	}
	if err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", s.env(r))
}

// newKeyAndLink saves a pasted key and links it into the environment, in
// place of what it linked before.
func (s *Server) newKeyAndLink(w http.ResponseWriter, r *http.Request) {
	env := s.env(r)
	svc := r.PathValue("id")
	if _, ok := s.Core.Environment(env.ID); !ok {
		s.servicesError(w, r, fmt.Errorf("environment %q: %w", env.ID, core.ErrNotFound))
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = s.freeKeyName(svc, env.ID+" "+svc)
	}
	k, err := s.Core.AddKey(r.Context(), core.KeySpec{ServiceID: svc, Name: name, Value: r.FormValue("key")})
	if err == nil {
		if _, err = s.Core.LinkKey(r.Context(), core.LinkSpec{EnvID: env.ID, ServiceID: svc, KeyID: k.ID}); err != nil {
			_ = s.Core.DeleteKey(r.Context(), k.ID) // not linked, so nothing uses it
		}
	}
	if err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", env)
}

func (s *Server) linkKey(w http.ResponseWriter, r *http.Request) {
	env := s.env(r)
	if _, err := s.Core.LinkKey(r.Context(), core.LinkSpec{EnvID: env.ID, ServiceID: r.PathValue("id"), KeyID: r.FormValue("key")}); err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", env)
}

func (s *Server) unlinkKey(w http.ResponseWriter, r *http.Request) {
	env := s.env(r)
	if err := s.Core.Unlink(r.Context(), env.ID, r.PathValue("id")); err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", env)
}

// freeKeyName is base, or base with " 2", " 3"… if a saved key for svc
// already has that name.
func (s *Server) freeKeyName(svc, base string) string {
	taken := map[string]bool{}
	for _, k := range s.Core.Keys() {
		if k.ServiceID == svc {
			taken[strings.ToLower(k.Name)] = true
		}
	}
	name := base
	for n := 2; taken[strings.ToLower(name)]; n++ {
		name = fmt.Sprintf("%s %d", base, n)
	}
	return name
}

// --- saved keys ---

type keyRow struct {
	core.SavedKey
	Service   string // its name
	LinkedIn  []string
	UsedToday int // counted only while it has a limit
}

type keysData struct {
	Rows     []keyRow
	Services []core.Service
}

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	names := map[string]string{}
	svcs := s.Core.Services()
	for _, svc := range svcs {
		names[svc.ID] = svc.Name
	}
	var d keysData
	for _, k := range s.Core.Keys() {
		row := keyRow{SavedKey: k, Service: names[k.ServiceID], LinkedIn: s.Core.KeyLinkedIn(k.ID)}
		if k.Limits != (core.Limits{}) { // only then counted
			row.UsedToday = s.Core.UsedToday(r.Context(), "key:"+k.ID)
		}
		d.Rows = append(d.Rows, row)
	}
	d.Services = svcs
	s.renderStatus(w, status, "keys", "Keys", errMsg, d, s.env(r))
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) { s.keysPage(w, r, http.StatusOK, "") }

func (s *Server) keyDone(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		s.keysPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	back(w, r, "/keys", s.env(r))
}

func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		_, err = s.Core.AddKey(r.Context(), core.KeySpec{ServiceID: r.FormValue("service"), Name: r.FormValue("name"), Value: r.FormValue("key"), Limits: limits})
	}
	s.keyDone(w, r, err)
}

func (s *Server) replaceKey(w http.ResponseWriter, r *http.Request) {
	_, err := s.Core.ReplaceKey(r.Context(), r.PathValue("id"), r.FormValue("key"))
	s.keyDone(w, r, err)
}

func (s *Server) renameKey(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	_, err := s.Core.UpdateKey(r.Context(), r.PathValue("id"), core.KeyChange{Name: &name})
	s.keyDone(w, r, err)
}

func (s *Server) keyLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		_, err = s.Core.UpdateKey(r.Context(), r.PathValue("id"), core.KeyChange{Limits: &limits})
	}
	s.keyDone(w, r, err)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	s.keyDone(w, r, s.Core.DeleteKey(r.Context(), r.PathValue("id")))
}

func (s *Server) removeService(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.RemoveService(r.Context(), r.PathValue("id")); err != nil {
		s.servicesError(w, r, err)
		return
	}
	back(w, r, "/services", s.env(r))
}

// --- tokens ---

type tokenRow struct {
	core.Token
	State     string
	UsedToday int
}

type tokensData struct {
	Rows     []tokenRow
	Services []core.Service // the ones the environment links, for service tokens
	NewToken string
	NewName  string
}

// rows lists an environment's tokens, newest first, with state and usage.
func (s *Server) rows(ctx context.Context, envID string) []tokenRow {
	var rows []tokenRow
	for _, t := range s.Core.Tokens(envID) {
		rows = append(rows, tokenRow{Token: t, State: s.Core.TokenState(t.ID), UsedToday: s.Core.UsedToday(ctx, "token:"+t.ID)})
	}
	return rows
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, status int, errMsg string, d tokensData) {
	env := s.env(r)
	d.Rows = s.rows(r.Context(), env.ID)
	for _, l := range s.Core.LinkStatuses(env.ID) {
		if l.Linked {
			d.Services = append(d.Services, l.Service)
		}
	}
	s.renderStatus(w, status, "tokens", "Tokens", errMsg, d, env)
}

func (s *Server) tokens(w http.ResponseWriter, r *http.Request) {
	s.tokensPage(w, r, http.StatusOK, "", tokensData{})
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	fail := func(err error) { s.tokensPage(w, r, http.StatusBadRequest, err.Error(), tokensData{}) }
	limits, err := formLimits(r)
	if err != nil {
		fail(err)
		return
	}
	ttl, err := parseTTL(r.FormValue("ttl"))
	if err != nil {
		fail(err)
		return
	}
	tok, t, err := s.Core.CreateToken(r.Context(), core.TokenSpec{
		EnvID: s.env(r).ID, Name: r.FormValue("name"),
		Service: r.FormValue("service"), Limits: limits, TTL: ttl,
	})
	if err != nil {
		fail(err)
		return
	}
	s.tokensPage(w, r, http.StatusOK, "", tokensData{NewToken: tok, NewName: t.Name})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.RevokeToken(r.Context(), r.PathValue("id")); err != nil {
		s.tokensPage(w, r, http.StatusBadRequest, err.Error(), tokensData{})
		return
	}
	back(w, r, "/tokens", s.env(r))
}

// --- machines ---

const maxPendingRows = 50

type machineRow struct {
	core.Machine
	Tokens   int // live tokens it holds
	Unmarked int // tokens of a revoked machine not yet marked revoked (a save failed)
}

type machinesData struct {
	Pending    []core.LinkRequest
	Machines   []machineRow
	DefaultEnv string
	// MorePending is how many waiting requests aren't listed: the list
	// shows the oldest maxPendingRows.
	MorePending int
	EdgeURL     string
	Approved    *core.Machine
	// Confirm is the request a typed code belongs to, shown before it is
	// approved, so the admin sees which machine it is.
	Confirm     *core.LinkRequest
	ConfirmCode string
	// Retry is set when an approval failed, and Ticked are the
	// environments ticked then, so the confirm step comes back as the
	// admin left it, none ticked included.
	Retry  bool
	Ticked map[string]bool
}

func (s *Server) machinesPage(w http.ResponseWriter, r *http.Request, status int, errMsg string, d machinesData) {
	live, unmarked := map[string]int{}, map[string]int{}
	for _, t := range s.Core.Tokens("") {
		if t.Principal == "" {
			continue
		}
		if s.Core.TokenState(t.ID) == "active" {
			live[t.Principal]++
		}
		if t.RevokedAt == nil {
			unmarked[t.Principal]++
		}
	}
	for _, m := range s.Core.Machines() {
		row := machineRow{Machine: m, Tokens: live[m.Principal()]}
		if m.Revoked() {
			row.Unmarked = unmarked[m.Principal()]
		}
		d.Machines = append(d.Machines, row)
	}
	d.Pending, d.DefaultEnv = s.Core.PendingLinks(), s.env(r).ID
	if len(d.Pending) > maxPendingRows {
		d.MorePending = len(d.Pending) - maxPendingRows
		d.Pending = d.Pending[:maxPendingRows]
	}
	d.EdgeURL = "https://<this server>"
	if s.EdgeAddr != "" {
		d.EdgeURL = "http://" + s.EdgeAddr
	}
	s.renderStatus(w, status, "machines", "Machines", errMsg, d, s.env(r))
}

func (s *Server) machines(w http.ResponseWriter, r *http.Request) {
	s.machinesPage(w, r, http.StatusOK, "", machinesData{})
}

func (s *Server) checkMachine(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	req, err := s.Core.PendingLink(code)
	if err != nil {
		s.machinesPage(w, r, http.StatusBadRequest, err.Error(), machinesData{})
		return
	}
	s.machinesPage(w, r, http.StatusOK, "", machinesData{Confirm: &req, ConfirmCode: code})
}

func (s *Server) approveMachine(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	if r.FormValue("action") == "deny" {
		if err := s.Core.DenyLink(code); err != nil {
			s.machinesPage(w, r, http.StatusBadRequest, err.Error(), machinesData{})
			return
		}
		back(w, r, "/machines", s.env(r))
		return
	}
	m, err := s.Core.ApproveLink(r.Context(), code, r.Form["envs"])
	if err != nil {
		d := machinesData{}
		if req, perr := s.Core.PendingLink(code); perr == nil {
			d.Confirm, d.ConfirmCode = &req, code // still waiting: stay on its confirm step
			d.Retry, d.Ticked = true, map[string]bool{}
			for _, id := range r.Form["envs"] {
				d.Ticked[id] = true
			}
		}
		s.machinesPage(w, r, http.StatusBadRequest, err.Error(), d)
		return
	}
	s.machinesPage(w, r, http.StatusOK, "", machinesData{Approved: &m})
}

func (s *Server) denyMachine(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.DenyLinkRequest(r.PathValue("id")); err != nil {
		s.machinesPage(w, r, http.StatusBadRequest, "that request is gone: it was approved, turned down or expired", machinesData{})
		return
	}
	back(w, r, "/machines", s.env(r))
}

func (s *Server) revokeMachine(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.RevokeMachine(r.Context(), r.PathValue("id")); err != nil {
		s.machinesPage(w, r, http.StatusBadRequest, err.Error(), machinesData{})
		return
	}
	back(w, r, "/machines", s.env(r))
}

// --- projects and environments ---

type projectRow struct {
	core.Project
	Envs []core.Environment
}

func (s *Server) projectsPage(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	var rows []projectRow
	envs := s.Core.Environments()
	for _, p := range s.Core.Projects() {
		row := projectRow{Project: p}
		for _, e := range envs {
			if e.ProjectID == p.ID {
				row.Envs = append(row.Envs, e)
			}
		}
		rows = append(rows, row)
	}
	s.renderStatus(w, status, "projects", "Projects", errMsg, rows, s.env(r))
}

func (s *Server) projects(w http.ResponseWriter, r *http.Request) {
	s.projectsPage(w, r, http.StatusOK, "")
}

func (s *Server) addProject(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		_, err = s.Core.AddProject(r.Context(), r.FormValue("name"), limits)
	}
	if err != nil {
		s.projectsPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

func (s *Server) projectLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		err = s.Core.SetProjectLimits(r.Context(), r.PathValue("id"), limits)
	}
	if err != nil {
		s.projectsPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

func (s *Server) addEnvironment(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		_, err = s.Core.AddEnvironment(r.Context(), r.FormValue("project"), r.FormValue("name"), limits)
	}
	if err != nil {
		s.projectsPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

func (s *Server) envLimits(w http.ResponseWriter, r *http.Request) {
	limits, err := formLimits(r)
	if err == nil {
		err = s.Core.SetEnvironmentLimits(r.Context(), r.FormValue("id"), limits)
	}
	if err != nil {
		s.projectsPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

func (s *Server) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.DeleteEnvironment(r.Context(), r.FormValue("id")); err != nil {
		s.projectsPage(w, r, http.StatusBadRequest, err.Error())
		return
	}
	http.Redirect(w, r, "/projects", http.StatusSeeOther)
}

// --- requests and setup ---

func (s *Server) requests(w http.ResponseWriter, r *http.Request) {
	s.renderStatus(w, http.StatusOK, "requests", "Requests", "", s.Log.Recent(200), s.env(r))
}

type setupData struct {
	ProxyAddr  string
	EdgeAddr   string
	QuickStart []string // "OPENAI_BASE_URL=http://…/s/openai/v1"
	CAPath     string
	BundlePath string
	SecretsIn  string
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	d := setupData{ProxyAddr: s.ProxyAddr, EdgeAddr: s.EdgeAddr, CAPath: s.CAPath, BundlePath: s.BundlePath, SecretsIn: s.SecretsIn}
	if s.EdgeAddr != "" {
		for _, svc := range s.Core.Services() {
			if svc.BaseURL.Var != "" {
				d.QuickStart = append(d.QuickStart, svc.BaseURL.Var+"=http://"+s.EdgeAddr+"/s/"+svc.ID+svc.BaseURL.Path)
			}
		}
	}
	s.renderStatus(w, http.StatusOK, "setup", "Setup", "", d, s.env(r))
}
