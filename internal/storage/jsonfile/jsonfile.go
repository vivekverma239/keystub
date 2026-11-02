// Package jsonfile is a Repository in one JSON file, written atomically.
// It suits a laptop or a single proxy; values in it are already sealed.
package jsonfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

const version = 3

// downgradeGuard fills the old "bindings" field. A build from before
// version 3 reads that field as a list, so it fails to start on this file
// instead of reading it without its saved keys and then saving over them.
const downgradeGuard = "converted to saved keys and links by a newer Keystub; this build is older than this file"

type state struct {
	Version      int                `json:"version"`
	Guard        string             `json:"bindings"` // downgradeGuard`
	Projects     []core.Project     `json:"projects"`
	Environments []core.Environment `json:"environments"`
	Services     []core.Service     `json:"services"`
	Keys         []core.SavedKey    `json:"keys"`
	Links        []core.Link        `json:"links"`
	Tokens       []core.Token       `json:"tokens"`
	Machines     []core.Machine     `json:"machines,omitempty"`
}

// stateV2 is the layout from before saved keys: one binding per service per environment,
// and tokens that may list services.
type stateV2 struct {
	Version      int                `json:"version"`
	Projects     []core.Project     `json:"projects"`
	Environments []core.Environment `json:"environments"`
	Services     []core.Service     `json:"services"`
	Bindings     []core.Binding     `json:"bindings"`
	Tokens       []core.OldToken    `json:"tokens"`
	Machines     []core.Machine     `json:"machines,omitempty"`
}

// Repo implements core.Repository.
type Repo struct {
	mu   sync.Mutex
	path string
	st   state
}

// Open reads path, or starts empty if it doesn't exist. An older file is
// converted, and kept beside it as "<path>.v1" or "<path>.v2":
//
//   - stage 0 (services holding their own key, a flat list of keys) moves
//     into the default project's dev environment;
//   - version 2 (one binding per service per environment) becomes a saved
//     key named "<env> <service>" and a link for each binding; its tokens
//     become environment tokens, or service tokens if they listed one
//     service, and those that listed several are revoked (see
//     core.OldToken.Upgrade).
//
// Notes says what the conversion changed that someone should know.
func Open(path string) (*Repo, error) {
	r, _, err := OpenNotes(path)
	return r, err
}

// OpenNotes is Open, also returning notes on what a conversion changed.
func OpenNotes(path string) (*Repo, []string, error) {
	r := &Repo{path: path, st: state{Version: version, Guard: downgradeGuard}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if probe.Version > version {
		return nil, nil, fmt.Errorf("read %s: it was written by a newer Keystub (version %d; this build reads up to %d)", path, probe.Version, version)
	}
	if probe.Version == version {
		if err := json.Unmarshal(b, &r.st); err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		return r, nil, nil
	}
	var old stateV2
	if probe.Version < 2 {
		old, err = migrateV1(b)
	} else {
		err = json.Unmarshal(b, &old)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	// A copy kept by an earlier start that stopped before saving is the
	// same file; a different one (the data went back to an older build)
	// is kept too, under another name.
	keep := fmt.Sprintf("%s.v%d", path, max(probe.Version, 1))
	if prev, err := os.ReadFile(keep); err == nil && !bytes.Equal(prev, b) {
		keep = fmt.Sprintf("%s.%s", keep, time.Now().UTC().Format("20060102T150405Z"))
	}
	if err := os.WriteFile(keep, b, 0o600); err != nil {
		return nil, nil, fmt.Errorf("keep a copy of %s before migrating: %w", path, err)
	}
	var notes []string
	r.st, notes = migrateV2(old)
	return r, notes, r.save()
}

// migrateV2 turns bindings into saved keys and links, and upgrades tokens.
func migrateV2(old stateV2) (state, []string) {
	st := state{Version: version, Guard: downgradeGuard, Projects: old.Projects, Environments: old.Environments, Services: old.Services, Machines: old.Machines}
	for _, b := range old.Bindings {
		k, l := core.FromBinding(b)
		st.Keys, st.Links = append(st.Keys, k), append(st.Links, l)
	}
	var notes []string
	st.Tokens, notes = core.UpgradeTokens(old.Tokens, time.Now())
	return st, notes
}

// migrateV1 converts the stage 0 layout to version 2.
func migrateV1(b []byte) (stateV2, error) {
	var old struct {
		Services []struct {
			core.Service
			Secret      *core.Sealed `json:"secret"`
			SecretSetAt time.Time    `json:"secretSetAt"`
		} `json:"services"`
		Keys []struct {
			ID         string       `json:"id"`
			Name       string       `json:"name"`
			TokenHash  string       `json:"tokenHash"`
			Token      *core.Sealed `json:"token"`
			DailyLimit int          `json:"dailyLimit"`
			CreatedAt  time.Time    `json:"createdAt"`
			RevokedAt  *time.Time   `json:"revokedAt"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &old); err != nil {
		return stateV2{}, err
	}
	now := time.Now().UTC()
	st := stateV2{
		Version:      2,
		Projects:     []core.Project{{ID: "default", Name: "Default", CreatedAt: now}},
		Environments: []core.Environment{{ID: core.DefaultEnv, ProjectID: "default", Name: "dev", CreatedAt: now}},
	}
	for _, s := range old.Services {
		st.Services = append(st.Services, s.Service)
		if s.Secret != nil {
			st.Bindings = append(st.Bindings, core.Binding{EnvID: core.DefaultEnv, ServiceID: s.ID, Secret: s.Secret, SetAt: s.SecretSetAt})
		}
	}
	for _, k := range old.Keys {
		st.Tokens = append(st.Tokens, core.OldToken{Token: core.Token{
			ID: k.ID, Name: k.Name, EnvID: core.DefaultEnv, TokenHash: k.TokenHash, Token: k.Token,
			Limits: core.Limits{DailyRequests: k.DailyLimit}, CreatedAt: k.CreatedAt, RevokedAt: k.RevokedAt,
		}})
	}
	return st, nil
}

func (r *Repo) save() error {
	b, err := json.MarshalIndent(r.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}

// put replaces the item matching same, or appends it, then saves. If the
// save fails, memory is left as it was, so a failed write never reaches
// the file later with someone else's save.
func put[T any](r *Repo, list *[]T, item T, same func(T) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := *list
	next := slices.Clone(old)
	if i := slices.IndexFunc(next, same); i >= 0 {
		next[i] = item
	} else {
		next = append(next, item)
	}
	*list = next
	if err := r.save(); err != nil {
		*list = old
		return err
	}
	return nil
}

// del removes the item matching same, then saves; like put, a failed save
// changes nothing.
func del[T any](r *Repo, list *[]T, same func(T) bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := *list
	i := slices.IndexFunc(old, same)
	if i < 0 {
		return core.ErrNotFound
	}
	*list = slices.Delete(slices.Clone(old), i, i+1)
	if err := r.save(); err != nil {
		*list = old
		return err
	}
	return nil
}

// list copies a field; it takes the field's address so it is read under
// the lock.
func list[T any](r *Repo, l *[]T) []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(*l)
}

func (r *Repo) ListProjects(context.Context) ([]core.Project, error) {
	return list(r, &r.st.Projects), nil
}

func (r *Repo) PutProject(_ context.Context, p core.Project) error {
	return put(r, &r.st.Projects, p, func(x core.Project) bool { return x.ID == p.ID })
}

func (r *Repo) ListEnvironments(context.Context) ([]core.Environment, error) {
	return list(r, &r.st.Environments), nil
}

func (r *Repo) PutEnvironment(_ context.Context, e core.Environment) error {
	return put(r, &r.st.Environments, e, func(x core.Environment) bool { return x.ID == e.ID })
}

func (r *Repo) DeleteEnvironment(_ context.Context, id string) error {
	return del(r, &r.st.Environments, func(x core.Environment) bool { return x.ID == id })
}

func (r *Repo) ListServices(context.Context) ([]core.Service, error) {
	return list(r, &r.st.Services), nil
}

func (r *Repo) PutService(_ context.Context, s core.Service) error {
	return put(r, &r.st.Services, s, func(x core.Service) bool { return x.ID == s.ID })
}

func (r *Repo) DeleteService(_ context.Context, id string) error {
	return del(r, &r.st.Services, func(x core.Service) bool { return x.ID == id })
}

func (r *Repo) ListKeys(context.Context) ([]core.SavedKey, error) {
	return list(r, &r.st.Keys), nil
}

func (r *Repo) PutKey(_ context.Context, k core.SavedKey) error {
	return put(r, &r.st.Keys, k, func(x core.SavedKey) bool { return x.ID == k.ID })
}

func (r *Repo) DeleteKey(_ context.Context, id string) error {
	return del(r, &r.st.Keys, func(x core.SavedKey) bool { return x.ID == id })
}

func (r *Repo) ListLinks(context.Context) ([]core.Link, error) {
	return list(r, &r.st.Links), nil
}

func (r *Repo) PutLink(_ context.Context, l core.Link) error {
	return put(r, &r.st.Links, l, func(x core.Link) bool { return x.EnvID == l.EnvID && x.ServiceID == l.ServiceID })
}

func (r *Repo) DeleteLink(_ context.Context, envID, serviceID string) error {
	return del(r, &r.st.Links, func(x core.Link) bool { return x.EnvID == envID && x.ServiceID == serviceID })
}

func (r *Repo) ListTokens(context.Context) ([]core.Token, error) {
	return list(r, &r.st.Tokens), nil
}

func (r *Repo) PutToken(_ context.Context, t core.Token) error {
	return put(r, &r.st.Tokens, t, func(x core.Token) bool { return x.ID == t.ID })
}

func (r *Repo) ListMachines(context.Context) ([]core.Machine, error) {
	return list(r, &r.st.Machines), nil
}

func (r *Repo) PutMachine(_ context.Context, m core.Machine) error {
	return put(r, &r.st.Machines, m, func(x core.Machine) bool { return x.ID == m.ID })
}
