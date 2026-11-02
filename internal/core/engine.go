package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine is the core. The proxy uses its data-plane methods (ServiceForHost,
// Authorize, RealKey); the dashboard and API use its control-plane methods.
// It keeps the model in memory, so the request path never waits on storage;
// every write goes to the Repository first.
//
// Two locks: wmu serialises writers for the whole write, storage included,
// and mu guards the in-memory model. A writer holds mu only to apply a
// change that storage has already accepted, so the data plane never waits
// on a disk write.
type Engine struct {
	repo    Repository
	sealer  Sealer
	limiter Limiter
	now     func() time.Time

	wmu      sync.Mutex
	mu       sync.RWMutex
	projects []Project
	envs     []Environment
	services []Service
	keys     []SavedKey
	keyLinks []Link
	tokens   []Token
	machines []Machine

	links linkRequests // machines waiting to be approved; in memory only
}

// NewEngine loads the model from repo. A fresh install gets the default
// project and its dev environment.
func NewEngine(ctx context.Context, repo Repository, sealer Sealer, limiter Limiter) (*Engine, error) {
	e := &Engine{repo: repo, sealer: sealer, limiter: limiter, now: time.Now}
	var err error
	if e.projects, err = repo.ListProjects(ctx); err != nil {
		return nil, fmt.Errorf("load projects: %w", err)
	}
	if e.envs, err = repo.ListEnvironments(ctx); err != nil {
		return nil, fmt.Errorf("load environments: %w", err)
	}
	if e.services, err = repo.ListServices(ctx); err != nil {
		return nil, fmt.Errorf("load services: %w", err)
	}
	if e.keys, err = repo.ListKeys(ctx); err != nil {
		return nil, fmt.Errorf("load saved keys: %w", err)
	}
	if e.keyLinks, err = repo.ListLinks(ctx); err != nil {
		return nil, fmt.Errorf("load links: %w", err)
	}
	if e.tokens, err = repo.ListTokens(ctx); err != nil {
		return nil, fmt.Errorf("load tokens: %w", err)
	}
	if e.machines, err = repo.ListMachines(ctx); err != nil {
		return nil, fmt.Errorf("load machines: %w", err)
	}
	if len(e.projects) == 0 {
		if _, err := e.AddProject(ctx, "Default", Limits{}); err != nil {
			return nil, err
		}
		if _, err := e.AddEnvironment(ctx, "default", "dev", Limits{}); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// SetClock replaces the clock, for tests.
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// apply changes the in-memory model. Callers hold wmu, and call it only
// after the repository has accepted the change.
func (e *Engine) apply(change func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	change()
}

func (e *Engine) seal(ctx context.Context, value string) (*Sealed, error) {
	v, err := e.sealer.Seal(ctx, []byte(value))
	if err != nil {
		return nil, err
	}
	v.Sealer = e.sealer.Name()
	return &v, nil
}

func (e *Engine) open(ctx context.Context, v *Sealed) (string, error) {
	name := v.Sealer
	if name == "" {
		name = "envelope"
	}
	if name != e.sealer.Name() {
		return "", fmt.Errorf("this value was sealed by %q, but Keystub is using %q", name, e.sealer.Name())
	}
	pt, err := e.sealer.Open(ctx, *v)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func strip(t Token) Token {
	t.Token = nil
	return t
}

func stripKey(k SavedKey) SavedKey {
	k.Secret = nil
	return k
}

// --- lookups (callers hold e.mu) ---

func (e *Engine) projectLocked(id string) (Project, bool) {
	for _, p := range e.projects {
		if p.ID == id {
			return p, true
		}
	}
	return Project{}, false
}

func (e *Engine) envLocked(id string) (Environment, bool) {
	for _, v := range e.envs {
		if v.ID == id {
			return v, true
		}
	}
	return Environment{}, false
}

func (e *Engine) serviceLocked(id string) (Service, bool) {
	for _, s := range e.services {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

func (e *Engine) keyLocked(id string) (SavedKey, bool) {
	for _, k := range e.keys {
		if k.ID == id {
			return k, true
		}
	}
	return SavedKey{}, false
}

func (e *Engine) linkLocked(envID, serviceID string) (Link, bool) {
	for _, l := range e.keyLinks {
		if l.EnvID == envID && l.ServiceID == serviceID {
			return l, true
		}
	}
	return Link{}, false
}

func (e *Engine) tokenLocked(id string) (Token, bool) {
	for _, t := range e.tokens {
		if t.ID == id {
			return t, true
		}
	}
	return Token{}, false
}

// --- data plane ---

// ServiceForHost returns the service that owns host, if any.
func (e *Engine) ServiceForHost(host string) (Service, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, s := range e.services {
		if s.Matches(host) {
			s.Hosts, s.EnvVars = slices.Clone(s.Hosts), slices.Clone(s.EnvVars)
			return s, true
		}
	}
	return Service{}, false
}

// Service returns a service by ID, for routes that name it (/s/openai/…).
func (e *Engine) Service(id string) (Service, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s, ok := e.serviceLocked(id)
	if ok {
		s.Hosts, s.EnvVars = slices.Clone(s.Hosts), slices.Clone(s.EnvVars)
	}
	return s, ok
}

// CheckToken reports whether token is a live proxy token, without counting
// anything. A proxy reachable from other machines uses it to refuse
// connections, tunnels included, that carry no valid token.
func (e *Engine) CheckToken(token string) error {
	token = Normalize(token)
	if !strings.HasPrefix(token, TokenPrefix) {
		return ErrUnknownKey
	}
	h := hashToken(token)
	e.mu.RLock()
	defer e.mu.RUnlock()
	i := slices.IndexFunc(e.tokens, func(t Token) bool { return t.TokenHash == h })
	switch {
	case i < 0 || e.tokens[i].Revoked() || e.ownerRevokedLocked(e.tokens[i]):
		return ErrUnknownKey
	case e.tokens[i].Expired(e.now()):
		return ErrExpired
	}
	return nil
}

// TokenServices returns a live token (without its secret) and the services
// it may use that its environment links, without counting anything. An agent that holds no keys asks for it to learn which hosts to
// decrypt and which variables to set; a service with no key there could
// only be refused, so its hosts are better left alone.
func (e *Engine) TokenServices(token string) (Token, []Service, error) {
	token = Normalize(token)
	if !strings.HasPrefix(token, TokenPrefix) {
		return Token{}, nil, ErrUnknownKey
	}
	h := hashToken(token)
	e.mu.RLock()
	defer e.mu.RUnlock()
	i := slices.IndexFunc(e.tokens, func(t Token) bool { return t.TokenHash == h })
	switch {
	case i < 0 || e.tokens[i].Revoked() || e.ownerRevokedLocked(e.tokens[i]):
		return Token{}, nil, ErrUnknownKey
	case e.tokens[i].Expired(e.now()):
		return Token{}, nil, ErrExpired
	}
	t := e.tokens[i]
	var out []Service
	for _, s := range e.services {
		if _, linked := e.linkLocked(t.EnvID, s.ID); t.Allows(s.ID) && linked {
			s.Hosts, s.EnvVars = slices.Clone(s.Hosts), slices.Clone(s.EnvVars)
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return strip(t), out, nil
}

// Grant is what Authorize found: the caller's token, where it lives, the
// saved key its environment links (without its value), and the real key to
// use. Key is plaintext: never log it.
type Grant struct {
	Token    Token
	Env      Environment
	Project  Project
	SavedKey SavedKey
	Key      string
}

// Authorize resolves a call to serviceID: the token (either form) gives
// the environment, the environment's link for the service gives the saved
// key, and the saved key gives the real key. It checks that the token is
// live and allows the service (a service token only its own), decrypts the
// real key, and only then counts the request against the project, the
// environment, the token and, when it has limits, the saved key. A request
// goes ahead only if every level has room.
func (e *Engine) Authorize(ctx context.Context, token, serviceID string) (Grant, error) {
	token = Normalize(token)
	if !strings.HasPrefix(token, TokenPrefix) {
		return Grant{}, ErrUnknownKey
	}
	h := hashToken(token)

	e.mu.RLock()
	var g Grant
	var sealed *Sealed
	err := func() error {
		idx := slices.IndexFunc(e.tokens, func(t Token) bool { return t.TokenHash == h })
		if idx < 0 {
			return ErrUnknownKey
		}
		t := e.tokens[idx]
		env, ok := e.envLocked(t.EnvID)
		if !ok {
			return ErrUnknownKey
		}
		proj, _ := e.projectLocked(env.ProjectID)
		g = Grant{Token: strip(t), Env: env, Project: proj}
		switch {
		case t.Revoked() || e.ownerRevokedLocked(t):
			return ErrUnknownKey
		case t.Expired(e.now()):
			return ErrExpired
		case !t.Allows(serviceID):
			return ErrNotAllowed
		}
		l, ok := e.linkLocked(env.ID, serviceID)
		if !ok {
			return ErrNotLinked
		}
		k, ok := e.keyLocked(l.KeyID)
		if !ok {
			return ErrNotLinked
		}
		g.SavedKey, sealed = stripKey(k), k.Secret
		return nil
	}()
	e.mu.RUnlock()
	if err != nil {
		return g, err
	}
	// Decrypted before counting, so a request Keystub can't serve uses up
	// no limit.
	key, err := e.open(ctx, sealed)
	if err != nil {
		return g, fmt.Errorf("%w: %v", ErrKeyUnreadable, err)
	}
	g.Key = key

	scopes := []Scope{
		{Key: "project:" + g.Project.ID, Label: "project " + g.Project.Name, Limits: g.Project.Limits},
		{Key: "env:" + g.Env.ID, Label: "environment " + g.Env.ID, Limits: g.Env.Limits},
		{Key: "token:" + g.Token.ID, Label: "token " + g.Token.Name, Limits: g.Token.Limits},
	}
	// A saved key is counted only while it has a limit: it can be shared by
	// many environments, and most never set one. The refusal goes to the
	// token's holder, who needn't know the key's name, so it names the
	// service; the dashboard shows the key.
	if l := g.SavedKey.Limits; l.DailyRequests > 0 || l.PerMinute > 0 {
		scopes = append(scopes, Scope{Key: "key:" + g.SavedKey.ID, Label: "the saved key for " + serviceID, Limits: l})
	}
	return g, e.limiter.Allow(ctx, scopes)
}

// RealKey decrypts the real key an environment links for a service.
func (e *Engine) RealKey(ctx context.Context, envID, serviceID string) (string, error) {
	e.mu.RLock()
	var secret *Sealed
	if l, ok := e.linkLocked(envID, serviceID); ok {
		if k, ok := e.keyLocked(l.KeyID); ok {
			secret = k.Secret
		}
	}
	e.mu.RUnlock()
	if secret == nil {
		return "", ErrNotLinked
	}
	return e.open(ctx, secret)
}

// --- control plane: projects and environments ---

// checkSlug explains why a name can't become an ID.
func checkSlug(what, slug string) error { // what: "a project", "an environment"
	switch {
	case slug == "":
		return fmt.Errorf("%s needs a name with letters or digits", what)
	case len(slug) > 64:
		return fmt.Errorf("%s name can be at most 64 letters and digits", what)
	case !idPattern.MatchString(slug):
		return fmt.Errorf("%q can't be used as %s name", slug, what)
	}
	return nil
}

// Projects lists projects by name.
func (e *Engine) Projects() []Project {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := slices.Clone(e.projects)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// AddProject creates a project; its ID is the name as a slug.
func (e *Engine) AddProject(ctx context.Context, name string, limits Limits) (Project, error) {
	name = strings.TrimSpace(name)
	id := Slug(name)
	if err := checkSlug("a project", id); err != nil {
		return Project{}, err
	}
	if err := limits.Validate(); err != nil {
		return Project{}, err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.projectLocked(id); ok {
		return Project{}, ErrNameTaken
	}
	p := Project{ID: id, Name: name, Limits: limits, CreatedAt: e.now().UTC()}
	if err := e.repo.PutProject(ctx, p); err != nil {
		return Project{}, err
	}
	e.apply(func() { e.projects = append(e.projects, p) })
	return p, nil
}

// SetProjectLimits changes a project's limits.
func (e *Engine) SetProjectLimits(ctx context.Context, id string, limits Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	for i := range e.projects {
		if e.projects[i].ID == id {
			p := e.projects[i]
			p.Limits = limits
			if err := e.repo.PutProject(ctx, p); err != nil {
				return err
			}
			e.apply(func() { e.projects[i] = p })
			return nil
		}
	}
	return ErrNotFound
}

// Environments lists environments by ID.
func (e *Engine) Environments() []Environment {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := slices.Clone(e.envs)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Environment returns one environment.
func (e *Engine) Environment(id string) (Environment, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.envLocked(id)
}

// AddEnvironment creates an environment in a project.
func (e *Engine) AddEnvironment(ctx context.Context, projectID, name string, limits Limits) (Environment, error) {
	slug := Slug(name)
	if err := checkSlug("an environment", slug); err != nil {
		return Environment{}, err
	}
	if err := limits.Validate(); err != nil {
		return Environment{}, err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.projectLocked(projectID); !ok {
		return Environment{}, fmt.Errorf("project %q: %w", projectID, ErrNotFound)
	}
	id := EnvID(projectID, slug)
	if _, ok := e.envLocked(id); ok {
		return Environment{}, ErrNameTaken
	}
	v := Environment{ID: id, ProjectID: projectID, Name: slug, Limits: limits, CreatedAt: e.now().UTC()}
	if err := e.repo.PutEnvironment(ctx, v); err != nil {
		return Environment{}, err
	}
	e.apply(func() { e.envs = append(e.envs, v) })
	return v, nil
}

// SetEnvironmentLimits changes an environment's limits.
func (e *Engine) SetEnvironmentLimits(ctx context.Context, id string, limits Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	for i := range e.envs {
		if e.envs[i].ID == id {
			v := e.envs[i]
			v.Limits = limits
			if err := e.repo.PutEnvironment(ctx, v); err != nil {
				return err
			}
			e.apply(func() { e.envs[i] = v })
			return nil
		}
	}
	return ErrNotFound
}

// DeleteEnvironment removes an environment: its tokens are revoked, its
// links removed, and machines stop being allowed to use it, so making an
// environment with the same name later brings none of them back. Saved
// keys stay. Memory follows storage step by step, tokens first, so a
// failure part way never leaves a token working.
func (e *Engine) DeleteEnvironment(ctx context.Context, id string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.envLocked(id); !ok {
		return ErrNotFound
	}
	at := e.now().UTC()
	for i := range e.tokens {
		if e.tokens[i].EnvID != id || e.tokens[i].Revoked() {
			continue
		}
		t := e.tokens[i]
		t.RevokedAt = &at
		if err := e.repo.PutToken(ctx, t); err != nil {
			return err
		}
		e.apply(func() { e.tokens[i] = t })
	}
	for _, l := range slices.Clone(e.keyLinks) {
		if l.EnvID != id {
			continue
		}
		if err := e.repo.DeleteLink(ctx, l.EnvID, l.ServiceID); err != nil {
			return err
		}
		e.apply(func() {
			e.keyLinks = slices.DeleteFunc(e.keyLinks, func(x Link) bool { return x.EnvID == id && x.ServiceID == l.ServiceID })
		})
	}
	for i := range e.machines {
		if !slices.Contains(e.machines[i].Envs, id) {
			continue
		}
		m := e.machines[i]
		m.Envs = slices.DeleteFunc(slices.Clone(m.Envs), func(x string) bool { return x == id })
		if err := e.repo.PutMachine(ctx, m); err != nil {
			return err
		}
		e.apply(func() { e.machines[i] = m })
	}
	if err := e.repo.DeleteEnvironment(ctx, id); err != nil {
		return err
	}
	e.apply(func() { e.envs = slices.DeleteFunc(e.envs, func(v Environment) bool { return v.ID == id }) })
	return nil
}

// --- control plane: services ---

// Services lists services by name.
func (e *Engine) Services() []Service {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Service, len(e.services))
	for i, s := range e.services {
		s.Hosts, s.EnvVars = slices.Clone(s.Hosts), slices.Clone(s.EnvVars)
		out[i] = s
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// AddService adds a service. An ID that exists already is refused
// (ErrNameTaken), whatever the rest says: a service's hosts decide where
// its real keys are sent, so they change only through UpdateService.
func (e *Engine) AddService(ctx context.Context, svc Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.serviceLocked(svc.ID); ok {
		return fmt.Errorf("service %q already exists: %w", svc.ID, ErrNameTaken)
	}
	if err := e.repo.PutService(ctx, svc); err != nil {
		return err
	}
	e.apply(func() { e.services = append(e.services, svc) })
	return nil
}

// UpdateService changes an existing service (svc.ID names it). While any
// saved key exists for it, a change is refused (*ServiceHasKeysError):
// its hosts and header decide where those keys go, so delete or move them
// first.
func (e *Engine) UpdateService(ctx context.Context, svc Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	i := slices.IndexFunc(e.services, func(s Service) bool { return s.ID == svc.ID })
	if i < 0 {
		return fmt.Errorf("service %q: %w", svc.ID, ErrNotFound)
	}
	var keys []string
	for _, k := range e.keys {
		if k.ServiceID == svc.ID {
			keys = append(keys, k.Name)
		}
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return &ServiceHasKeysError{Service: svc.ID, Keys: keys}
	}
	if err := e.repo.PutService(ctx, svc); err != nil {
		return err
	}
	e.apply(func() { e.services[i] = svc })
	return nil
}

// RemoveService deletes a service, its links in every environment and its
// saved keys. Memory follows storage step by step, links first, so a
// failure part way leaves the two agreeing on what is left and never a
// link to a deleted key.
func (e *Engine) RemoveService(ctx context.Context, id string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.serviceLocked(id); !ok {
		return ErrNotFound
	}
	for _, l := range slices.Clone(e.keyLinks) {
		if l.ServiceID != id {
			continue
		}
		if err := e.repo.DeleteLink(ctx, l.EnvID, l.ServiceID); err != nil {
			return err
		}
		e.apply(func() {
			e.keyLinks = slices.DeleteFunc(e.keyLinks, func(x Link) bool { return x.EnvID == l.EnvID && x.ServiceID == id })
		})
	}
	for _, k := range slices.Clone(e.keys) {
		if k.ServiceID != id {
			continue
		}
		if err := e.repo.DeleteKey(ctx, k.ID); err != nil {
			return err
		}
		e.apply(func() { e.keys = slices.DeleteFunc(e.keys, func(x SavedKey) bool { return x.ID == k.ID }) })
	}
	if err := e.repo.DeleteService(ctx, id); err != nil {
		return err
	}
	e.apply(func() {
		e.services = slices.DeleteFunc(e.services, func(s Service) bool { return s.ID == id })
	})
	return nil
}

// --- control plane: saved keys ---

// maxKeyValue is the longest real key Keystub stores: room for a cloud
// service account's JSON, not for a file.
const maxKeyValue = 64 << 10

func checkKeyValue(v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return "", errors.New("key is empty")
	case len(v) > maxKeyValue:
		return "", errors.New("key is longer than 64 KiB")
	}
	return v, nil
}

func checkKeyName(n string) (string, error) {
	n = strings.TrimSpace(n)
	switch {
	case n == "":
		return "", errors.New("a saved key needs a name")
	case len(n) > 128:
		return "", errors.New("a saved key's name can be at most 128 characters")
	case strings.ContainsFunc(n, func(r rune) bool { return r < ' ' || r == 0x7f }):
		return "", errors.New("a saved key's name can't hold control characters")
	}
	return n, nil
}

func (e *Engine) keyNameTakenLocked(serviceID, name, except string) bool {
	return slices.ContainsFunc(e.keys, func(k SavedKey) bool {
		return k.ServiceID == serviceID && k.ID != except && strings.EqualFold(k.Name, name)
	})
}

// Keys lists saved keys, without their values, by service then name.
func (e *Engine) Keys() []SavedKey {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]SavedKey, len(e.keys))
	for i, k := range e.keys {
		out[i] = stripKey(k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServiceID != out[j].ServiceID {
			return out[i].ServiceID < out[j].ServiceID
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// Key returns one saved key, without its value.
func (e *Engine) Key(id string) (SavedKey, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	k, ok := e.keyLocked(id)
	return stripKey(k), ok
}

// KeyLinkedIn lists the environments that link a saved key, sorted.
func (e *Engine) KeyLinkedIn(id string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkedInLocked(id)
}

func (e *Engine) linkedInLocked(id string) []string {
	out := []string{}
	for _, l := range e.keyLinks {
		if l.KeyID == id {
			out = append(out, l.EnvID)
		}
	}
	sort.Strings(out)
	return out
}

// KeySpec describes a saved key to add.
type KeySpec struct {
	ServiceID string
	Name      string
	Value     string // the real key; never logged or returned
	Limits    Limits
}

// AddKey saves a real key for a service. Names are unique per service,
// ignoring case.
func (e *Engine) AddKey(ctx context.Context, spec KeySpec) (SavedKey, error) {
	name, err := checkKeyName(spec.Name)
	if err != nil {
		return SavedKey{}, err
	}
	value, err := checkKeyValue(spec.Value)
	if err != nil {
		return SavedKey{}, err
	}
	if err := spec.Limits.Validate(); err != nil {
		return SavedKey{}, err
	}
	sealed, err := e.seal(ctx, value)
	if err != nil {
		return SavedKey{}, err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.serviceLocked(spec.ServiceID); !ok {
		return SavedKey{}, fmt.Errorf("service %q: %w", spec.ServiceID, ErrNotFound)
	}
	if e.keyNameTakenLocked(spec.ServiceID, name, "") {
		return SavedKey{}, fmt.Errorf("a saved key for %s is already named %q: %w", spec.ServiceID, name, ErrNameTaken)
	}
	now := e.now().UTC()
	k := SavedKey{ID: NewID("key_"), Name: name, ServiceID: spec.ServiceID, Secret: sealed, Version: 1, SetAt: now, Limits: spec.Limits, CreatedAt: now}
	if err := e.repo.PutKey(ctx, k); err != nil {
		return SavedKey{}, err
	}
	e.apply(func() { e.keys = append(e.keys, k) })
	return stripKey(k), nil
}

// ReplaceKey rotates a saved key's value. Its version goes up, and every
// environment that links it uses the new value from the next request.
func (e *Engine) ReplaceKey(ctx context.Context, id, value string) (SavedKey, error) {
	value, err := checkKeyValue(value)
	if err != nil {
		return SavedKey{}, err
	}
	sealed, err := e.seal(ctx, value)
	if err != nil {
		return SavedKey{}, err
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	i := slices.IndexFunc(e.keys, func(k SavedKey) bool { return k.ID == id })
	if i < 0 {
		return SavedKey{}, ErrNotFound
	}
	k := e.keys[i]
	k.Secret, k.Version, k.SetAt = sealed, k.Version+1, e.now().UTC()
	if err := e.repo.PutKey(ctx, k); err != nil {
		return SavedKey{}, err
	}
	e.apply(func() { e.keys[i] = k })
	return stripKey(k), nil
}

// KeyChange is what UpdateKey changes; nil fields stay as they are.
type KeyChange struct {
	Name   *string
	Limits *Limits
}

// UpdateKey renames a saved key or changes its limits.
func (e *Engine) UpdateKey(ctx context.Context, id string, c KeyChange) (SavedKey, error) {
	var name string
	if c.Name != nil {
		n, err := checkKeyName(*c.Name)
		if err != nil {
			return SavedKey{}, err
		}
		name = n
	}
	if c.Limits != nil {
		if err := c.Limits.Validate(); err != nil {
			return SavedKey{}, err
		}
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	i := slices.IndexFunc(e.keys, func(k SavedKey) bool { return k.ID == id })
	if i < 0 {
		return SavedKey{}, ErrNotFound
	}
	k := e.keys[i]
	if c.Name != nil {
		if e.keyNameTakenLocked(k.ServiceID, name, k.ID) {
			return SavedKey{}, fmt.Errorf("a saved key for %s is already named %q: %w", k.ServiceID, name, ErrNameTaken)
		}
		k.Name = name
	}
	if c.Limits != nil {
		k.Limits = *c.Limits
	}
	if err := e.repo.PutKey(ctx, k); err != nil {
		return SavedKey{}, err
	}
	e.apply(func() { e.keys[i] = k })
	return stripKey(k), nil
}

// DeleteKey deletes a saved key. One that is still linked can't be
// deleted: the *KeyInUseError names the environments that link it.
func (e *Engine) DeleteKey(ctx context.Context, id string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.keyLocked(id); !ok {
		return ErrNotFound
	}
	if envs := e.linkedInLocked(id); len(envs) > 0 {
		return &KeyInUseError{Envs: envs}
	}
	if err := e.repo.DeleteKey(ctx, id); err != nil {
		return err
	}
	e.apply(func() { e.keys = slices.DeleteFunc(e.keys, func(k SavedKey) bool { return k.ID == id }) })
	return nil
}

// --- control plane: links ---

// Links lists an environment's links ("" for all), by environment then
// service.
func (e *Engine) Links(envID string) []Link {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Link
	for _, l := range e.keyLinks {
		if envID == "" || l.EnvID == envID {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EnvID != out[j].EnvID {
			return out[i].EnvID < out[j].EnvID
		}
		return out[i].ServiceID < out[j].ServiceID
	})
	return out
}

// LinkStatus is a service and the saved key an environment links for it,
// if any.
type LinkStatus struct {
	Service Service
	Linked  bool
	Link    Link
	Key     SavedKey // without its value
}

// LinkStatuses lists every service with what envID links for it.
func (e *Engine) LinkStatuses(envID string) []LinkStatus {
	svcs := e.Services()
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]LinkStatus, len(svcs))
	for i, s := range svcs {
		out[i] = LinkStatus{Service: s}
		if l, ok := e.linkLocked(envID, s.ID); ok {
			k, _ := e.keyLocked(l.KeyID)
			out[i].Linked, out[i].Link, out[i].Key = true, l, stripKey(k)
		}
	}
	return out
}

// LinkSpec says which saved key an environment uses for a service. When
// it makes a new link, ServiceToken also makes a service token for it,
// named TokenName (default: the service's ID, with -2, -3… if taken).
type LinkSpec struct {
	EnvID        string
	ServiceID    string
	KeyID        string
	ServiceToken bool
	TokenName    string
}

// LinkResult is what LinkKey did. Token and Secret are set when it made a
// service token; Secret is shown once.
type LinkResult struct {
	Link    Link
	Created bool // a new link, rather than an existing one switched or kept
	Token   *Token
	Secret  string
}

// LinkKey links a saved key into an environment for its service. A new
// link can make a service token; pointing an existing link at another
// saved key bumps its version and makes none, and every token of the
// environment moves to that key on its next request.
func (e *Engine) LinkKey(ctx context.Context, spec LinkSpec) (LinkResult, error) {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.envLocked(spec.EnvID); !ok {
		return LinkResult{}, fmt.Errorf("environment %q: %w", spec.EnvID, ErrNotFound)
	}
	if _, ok := e.serviceLocked(spec.ServiceID); !ok {
		return LinkResult{}, fmt.Errorf("service %q: %w", spec.ServiceID, ErrNotFound)
	}
	k, ok := e.keyLocked(spec.KeyID)
	if !ok {
		return LinkResult{}, fmt.Errorf("saved key %q: %w", spec.KeyID, ErrNotFound)
	}
	if k.ServiceID != spec.ServiceID {
		return LinkResult{}, fmt.Errorf("saved key %q is for %s, not %s", k.Name, k.ServiceID, spec.ServiceID)
	}
	now := e.now().UTC()
	old, exists := e.linkLocked(spec.EnvID, spec.ServiceID)
	if exists {
		if old.KeyID == k.ID {
			return LinkResult{Link: old}, nil
		}
		l := old
		l.KeyID, l.Version, l.SetAt = k.ID, old.Version+1, now
		if err := e.repo.PutLink(ctx, l); err != nil {
			return LinkResult{}, err
		}
		e.apply(func() {
			i := slices.IndexFunc(e.keyLinks, func(x Link) bool { return x.EnvID == l.EnvID && x.ServiceID == l.ServiceID })
			e.keyLinks[i] = l
		})
		return LinkResult{Link: l}, nil
	}

	var tokenName string
	if spec.ServiceToken {
		// Picked before the link is written, so a name that is taken fails
		// the whole call instead of leaving a link without its token.
		var err error
		if tokenName, err = e.serviceTokenNameLocked(spec.EnvID, spec.ServiceID, spec.TokenName); err != nil {
			return LinkResult{}, err
		}
	}
	l := Link{EnvID: spec.EnvID, ServiceID: spec.ServiceID, KeyID: k.ID, Version: 1, SetAt: now}
	if err := e.repo.PutLink(ctx, l); err != nil {
		return LinkResult{}, err
	}
	e.apply(func() { e.keyLinks = append(e.keyLinks, l) })
	res := LinkResult{Link: l, Created: true}
	if spec.ServiceToken {
		secret, t, err := e.create(ctx, TokenSpec{EnvID: spec.EnvID, Name: tokenName, Service: spec.ServiceID})
		if err != nil {
			// Undo the link, so asking again makes both rather than
			// finding the link and making no token.
			if derr := e.repo.DeleteLink(ctx, l.EnvID, l.ServiceID); derr != nil {
				return res, fmt.Errorf("linked, but the service token wasn't made: %w", err)
			}
			e.apply(func() {
				e.keyLinks = slices.DeleteFunc(e.keyLinks, func(x Link) bool { return x.EnvID == l.EnvID && x.ServiceID == l.ServiceID })
			})
			return LinkResult{}, fmt.Errorf("the service token wasn't made, so nothing was linked: %w", err)
		}
		res.Token, res.Secret = &t, secret
	}
	return res, nil
}

// serviceTokenNameLocked picks a new service token's name: the one asked
// for, which must be free, else the service's ID, with -2, -3… if taken.
func (e *Engine) serviceTokenNameLocked(envID, serviceID, asked string) (string, error) {
	if asked = strings.TrimSpace(asked); asked != "" {
		if e.tokenNameTakenLocked(envID, asked) {
			return "", fmt.Errorf("a live token in %s is already named %q: %w", envID, asked, ErrNameTaken)
		}
		return asked, nil
	}
	name := serviceID
	for n := 2; e.tokenNameTakenLocked(envID, name); n++ {
		name = fmt.Sprintf("%s-%d", serviceID, n)
	}
	return name, nil
}

func (e *Engine) tokenNameTakenLocked(envID, name string) bool {
	now := e.now()
	return slices.ContainsFunc(e.tokens, func(t Token) bool {
		return t.EnvID == envID && t.Name == name && t.Usable(now) && !e.ownerRevokedLocked(t)
	})
}

// Unlink removes an environment's link for a service. Its tokens are
// refused for that service, and its service tokens for it stop working,
// until the service is linked again. The saved key stays.
func (e *Engine) Unlink(ctx context.Context, envID, serviceID string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	if _, ok := e.linkLocked(envID, serviceID); !ok {
		return ErrNotFound
	}
	if err := e.repo.DeleteLink(ctx, envID, serviceID); err != nil {
		return err
	}
	e.apply(func() {
		e.keyLinks = slices.DeleteFunc(e.keyLinks, func(l Link) bool { return l.EnvID == envID && l.ServiceID == serviceID })
	})
	return nil
}

// --- control plane: tokens ---

// TokenSpec describes a token to create.
type TokenSpec struct {
	EnvID     string
	Name      string
	Principal string
	Service   string // "": an environment token; else a service token for this service, which env must link
	Limits    Limits
	TTL       time.Duration // 0: no expiry
}

// Tokens lists an environment's tokens ("" for all), newest first.
func (e *Engine) Tokens(envID string) []Token {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []Token
	for _, t := range e.tokens {
		if envID == "" || t.EnvID == envID {
			out = append(out, strip(t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// CreateToken makes a token and returns its secret value.
func (e *Engine) CreateToken(ctx context.Context, spec TokenSpec) (string, Token, error) {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	return e.create(ctx, spec)
}

func (e *Engine) create(ctx context.Context, spec TokenSpec) (string, Token, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	switch {
	case spec.Name == "":
		return "", Token{}, errors.New("a token needs a name")
	case len(spec.Name) > maxTokenName:
		return "", Token{}, fmt.Errorf("a token name can be at most %d characters", maxTokenName)
	case strings.ContainsFunc(spec.Name, func(r rune) bool { return r < ' ' || r == 0x7f }):
		return "", Token{}, errors.New("a token name can't hold control characters")
	}
	if err := spec.Limits.Validate(); err != nil {
		return "", Token{}, err
	}
	if spec.TTL < 0 {
		return "", Token{}, errors.New("lifetime can't be negative")
	}
	now := e.now().UTC()
	var expires *time.Time
	if spec.TTL > 0 {
		t := now.Add(spec.TTL)
		expires = &t
	}

	if _, ok := e.envLocked(spec.EnvID); !ok {
		return "", Token{}, fmt.Errorf("environment %q: %w", spec.EnvID, ErrNotFound)
	}
	kind := KindEnvironment
	if spec.Service != "" {
		if _, ok := e.serviceLocked(spec.Service); !ok {
			return "", Token{}, fmt.Errorf("service %q: %w", spec.Service, ErrNotFound)
		}
		if _, ok := e.linkLocked(spec.EnvID, spec.Service); !ok {
			return "", Token{}, fmt.Errorf("%s in %s: %w", spec.Service, spec.EnvID, ErrNotLinked)
		}
		kind = KindService
	}
	if e.tokenNameTakenLocked(spec.EnvID, spec.Name) {
		return "", Token{}, ErrNameTaken
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", Token{}, err
	}
	secret := TokenPrefix + hex.EncodeToString(b[:18])
	sealed, err := e.seal(ctx, secret)
	if err != nil {
		return "", Token{}, err
	}
	t := Token{
		ID: "tk_" + hex.EncodeToString(b[18:]), Name: spec.Name, EnvID: spec.EnvID,
		Principal: spec.Principal, Kind: kind, Service: spec.Service, Limits: spec.Limits, ExpiresAt: expires,
		TokenHash: hashToken(secret), Token: sealed, CreatedAt: now,
	}
	if err := e.repo.PutToken(ctx, t); err != nil {
		return "", Token{}, err
	}
	e.apply(func() { e.tokens = append(e.tokens, t) })
	return secret, strip(t), nil
}

// EnsureToken returns the live token with this name in envID,
// creating it if needed. `keystub run` uses it so each worktree keeps one.
func (e *Engine) EnsureToken(ctx context.Context, envID, name string) (string, Token, error) {
	name = strings.TrimSpace(name)
	e.wmu.Lock()
	defer e.wmu.Unlock()
	now := e.now()
	for _, t := range e.tokens {
		if t.EnvID == envID && t.Name == name && t.Usable(now) && !e.ownerRevokedLocked(t) {
			// Only a token EnsureToken made is handed out again: any other
			// (a CI job's, or a link's service token named after its
			// service) stays with whoever made it.
			if t.Principal != PrincipalRun {
				return "", Token{}, fmt.Errorf("%s already has a token named %q that keystub run didn't make; pick another name: %w", envID, name, ErrNameTaken)
			}
			secret, err := e.open(ctx, t.Token)
			return secret, strip(t), err
		}
	}
	return e.create(ctx, TokenSpec{EnvID: envID, Name: name, Principal: PrincipalRun})
}

// RevokeToken stops a token.
func (e *Engine) RevokeToken(ctx context.Context, id string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	for i := range e.tokens {
		if e.tokens[i].ID == id {
			if e.tokens[i].Revoked() {
				return nil
			}
			t := e.tokens[i]
			at := e.now().UTC()
			t.RevokedAt = &at
			if err := e.repo.PutToken(ctx, t); err != nil {
				return err
			}
			e.apply(func() { e.tokens[i] = t })
			return nil
		}
	}
	return ErrNotFound
}

// TokenState is "active", "revoked" or "expired", for display.
func (e *Engine) TokenState(id string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	t, ok := e.tokenLocked(id)
	if !ok {
		return "unknown"
	}
	now := e.now()
	switch {
	case t.Revoked() || e.ownerRevokedLocked(t):
		return "revoked"
	case t.Expired(now):
		return "expired"
	}
	return "active"
}

// UsedToday returns today's request count for a scope key, e.g. "token:tk_1".
func (e *Engine) UsedToday(ctx context.Context, key string) int {
	n, _ := e.limiter.UsedToday(ctx, key)
	return n
}
