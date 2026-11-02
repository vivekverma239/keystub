package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Linking a machine is a device-code flow. The CLI starts a request and
// shows its user code; an admin types that code on the dashboard and picks
// the environments the machine may use; the CLI, polling with its device
// code, then receives the machine's credential, once.
// MachineTokenLifetime is how long a token a machine minted lasts. Asked
// for again with under half of it left, a token gets a full one again.
const MachineTokenLifetime = 30 * 24 * time.Hour

const (
	LinkLifetime   = 10 * time.Minute
	LinkInterval   = 2 * time.Second // how often the CLI may poll
	maxPendingLink = 10000           // a few hundred bytes each; high enough that filling it takes a thousand networks
	maxLinksFrom   = 3               // pending requests from one source (an IPv4 address, an IPv6 /64)
	maxLinksNet    = 10              // pending requests from one network (an IPv4 /24, an IPv6 /48)
	maxDenied      = 100             // turned-down requests remembered, to answer their polls
	maxMachineToks = 100             // live tokens per machine
	maxTokenName   = 128             // a worktree name
	approvedGrace  = time.Minute     // a request approved near its end stays this long, for the CLI's last poll
	lastSeenEvery  = time.Minute     // how stale LastSeen may be before it is saved again
)

// userCodeAlphabet has no vowels or look-alikes (0/O, 1/I/L), so a code is
// easy to read out and never spells a word.
const userCodeAlphabet = "BCDFGHJKMNPQRSTVWXZ23456789"

// LinkStart is what the CLI gets when it starts linking.
type LinkStart struct {
	DeviceCode string // secret: the CLI polls with it
	UserCode   string // shown to the person, typed by the admin, e.g. "BCDF-2345"
	ExpiresAt  time.Time
}

// LinkRequest is a machine waiting to be approved, as the dashboard shows
// it. It never carries the user code: the admin types it from the CLI, so
// a request from somewhere else can't be approved by mistake.
type LinkRequest struct {
	ID        string // opaque, to turn it down from the list
	Name      string
	From      string // the address it came from
	CreatedAt time.Time
	ExpiresAt time.Time
}

type linkRequest struct {
	LinkRequest
	deviceHash string
	userCode   string
	source     string
	network    string
	machine    *Machine // set once approved
	credential string   // handed over once, then the request is gone
}

type linkRequests struct {
	mu   sync.Mutex
	reqs []*linkRequest // oldest first
	// Indexes of reqs, so a poll or a start doesn't scan thousands.
	byDevice map[string]*linkRequest
	byCode   map[string]*linkRequest
	fromSrc  map[string]int
	fromNet  map[string]int
	next     time.Time // no request expires before this
	// denied are turned-down requests: out of reqs at once, so they hold
	// no slot, but remembered until they expire to answer the CLI's poll.
	denied []deniedLink
}

type deniedLink struct {
	deviceHash string
	expiresAt  time.Time
}

// add adds a request. Callers hold mu.
func (l *linkRequests) add(r *linkRequest) {
	if l.byDevice == nil {
		l.byDevice, l.byCode, l.fromSrc, l.fromNet = map[string]*linkRequest{}, map[string]*linkRequest{}, map[string]int{}, map[string]int{}
	}
	if len(l.reqs) == 0 || r.ExpiresAt.Before(l.next) {
		l.next = r.ExpiresAt
	}
	l.reqs = append(l.reqs, r)
	l.byDevice[r.deviceHash] = r
	l.byCode[r.userCode] = r
	l.fromSrc[r.source]++
	l.fromNet[r.network]++
}

// forget takes r out of the indexes. Callers hold mu and drop r from reqs.
func (l *linkRequests) forget(r *linkRequest) {
	delete(l.byDevice, r.deviceHash)
	delete(l.byCode, r.userCode)
	dec := func(m map[string]int, k string) {
		if m[k]--; m[k] <= 0 {
			delete(m, k)
		}
	}
	dec(l.fromSrc, r.source)
	dec(l.fromNet, r.network)
}

// remove drops request i. Callers hold mu.
func (l *linkRequests) remove(i int) *linkRequest {
	r := l.reqs[i]
	l.reqs = slices.Delete(l.reqs, i, i+1)
	l.forget(r)
	return r
}

// prune drops expired requests. Callers hold mu.
func (l *linkRequests) prune(now time.Time) {
	if len(l.reqs) > 0 && !now.Before(l.next) {
		l.next = time.Time{}
		l.reqs = slices.DeleteFunc(l.reqs, func(r *linkRequest) bool {
			if now.Before(r.ExpiresAt) {
				if l.next.IsZero() || r.ExpiresAt.Before(l.next) {
					l.next = r.ExpiresAt
				}
				return false
			}
			l.forget(r)
			return true
		})
	}
	l.denied = slices.DeleteFunc(l.denied, func(d deniedLink) bool { return !now.Before(d.expiresAt) })
}

// deny turns down request i. Callers hold mu.
func (l *linkRequests) deny(i int) {
	r := l.remove(i)
	l.denied = append(l.denied, deniedLink{r.deviceHash, r.ExpiresAt})
	if len(l.denied) > maxDenied {
		l.denied = l.denied[len(l.denied)-maxDenied:]
	}
}

// linkSources are what the per-source caps count by: the address (for
// IPv6 its /64, which one host holds whole), and a wider network around it
// (an IPv4 /24, an IPv6 /48, which one home or tunnel can hold).
func linkSources(from string) (source, network string) {
	a, err := netip.ParseAddr(from)
	if err != nil {
		return from, from
	}
	a = a.WithZone("").Unmap()
	prefix := func(bits int) string { p, _ := a.Prefix(bits); return p.String() }
	if a.Is4() {
		return a.String(), prefix(24)
	}
	return prefix(64), prefix(48)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func userCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(c)%len(userCodeAlphabet)])
	}
	return string(out), nil
}

// normalizeCode accepts a typed code in any case, with or without the dash
// or spaces.
func normalizeCode(c string) string {
	c = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(c))
	if len(c) != 8 {
		return c
	}
	return c[:4] + "-" + c[4:]
}

func checkMachineName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", errors.New("a machine needs a name")
	case len(name) > 64:
		return "", errors.New("a machine name can be at most 64 characters")
	case strings.Contains(name, "/") || strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) }):
		// Cf: bidi overrides and zero-width characters, which could make
		// a name read as another machine's on the confirm step.
		return "", errors.New("a machine name can't contain /, control or invisible characters")
	}
	return name, nil
}

// StartLink opens a link request for a machine called name, from addr.
func (e *Engine) StartLink(name, from string) (LinkStart, error) {
	name, err := checkMachineName(name)
	if err != nil {
		return LinkStart{}, err
	}
	device, err := randomHex(32)
	if err != nil {
		return LinkStart{}, err
	}
	code, err := userCode()
	if err != nil {
		return LinkStart{}, err
	}
	rid, err := randomHex(8)
	if err != nil {
		return LinkStart{}, err
	}
	now := e.now()
	r := &linkRequest{
		LinkRequest: LinkRequest{ID: "lr_" + rid, Name: name, From: from, CreatedAt: now, ExpiresAt: now.Add(LinkLifetime)},
		deviceHash:  hashToken(device), userCode: code,
	}
	r.source, r.network = linkSources(from)
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	e.links.prune(now)
	// Starting needs no credential, so one source, or one network, can't
	// take more than a few of the slots.
	if len(e.links.reqs) >= maxPendingLink || e.links.fromSrc[r.source] >= maxLinksFrom || e.links.fromNet[r.network] >= maxLinksNet {
		return LinkStart{}, ErrTooManyLinks
	}
	if _, dup := e.links.byCode[code]; dup {
		return LinkStart{}, errors.New("couldn't pick a unique code; try again")
	}
	e.links.add(r)
	return LinkStart{DeviceCode: device, UserCode: code, ExpiresAt: r.ExpiresAt}, nil
}

// PendingLinks lists the machines waiting to be approved, oldest first.
func (e *Engine) PendingLinks() []LinkRequest {
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	e.links.prune(e.now())
	var out []LinkRequest
	for _, r := range e.links.reqs {
		if r.machine == nil {
			out = append(out, r.LinkRequest)
		}
	}
	return out
}

// PendingLink returns the request waiting with this user code, so the
// admin sees which machine it is before approving it.
func (e *Engine) PendingLink(code string) (LinkRequest, error) {
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	i, err := e.takeLink(code)
	if err != nil {
		return LinkRequest{}, err
	}
	return e.links.reqs[i].LinkRequest, nil
}

// PollLink is the CLI asking whether its request was approved. Once it
// was, the machine and its credential come back exactly once.
func (e *Engine) PollLink(deviceCode string) (Machine, string, error) {
	h := hashToken(deviceCode)
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	e.links.prune(e.now())
	// A map lookup by the secret's hash leaks nothing about the secret.
	r, ok := e.links.byDevice[h]
	if !ok {
		if slices.ContainsFunc(e.links.denied, func(d deniedLink) bool {
			return subtle.ConstantTimeCompare([]byte(d.deviceHash), []byte(h)) == 1
		}) {
			return Machine{}, "", ErrLinkDenied
		}
		return Machine{}, "", ErrLinkExpired
	}
	if r.machine == nil {
		return Machine{}, "", ErrLinkPending
	}
	e.links.remove(slices.Index(e.links.reqs, r))
	return stripMachine(*r.machine), r.credential, nil
}

// takeLink finds the pending request with this user code. Callers hold
// e.links.mu.
func (e *Engine) takeLink(code string) (int, error) {
	e.links.prune(e.now())
	code = normalizeCode(code)
	r, ok := e.links.byCode[code]
	i := slices.Index(e.links.reqs, r)
	if !ok || r.machine != nil || i < 0 {
		return -1, fmt.Errorf("no machine is waiting with code %s; codes last %v", code, LinkLifetime)
	}
	return i, nil
}

// ApproveLink approves the machine waiting with this user code, allowing it
// the given environments, and creates it.
func (e *Engine) ApproveLink(ctx context.Context, code string, envs []string) (Machine, error) {
	envs = slices.Compact(slices.Sorted(slices.Values(envs)))
	if len(envs) == 0 {
		return Machine{}, errors.New("pick at least one environment the machine may use")
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	e.mu.RLock()
	for _, id := range envs {
		if _, ok := e.envLocked(id); !ok {
			e.mu.RUnlock()
			return Machine{}, fmt.Errorf("environment %q: %w", id, ErrNotFound)
		}
	}
	e.mu.RUnlock()

	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	i, err := e.takeLink(code)
	if err != nil {
		return Machine{}, err
	}
	r := e.links.reqs[i]
	id, err := randomHex(6)
	if err != nil {
		return Machine{}, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return Machine{}, err
	}
	credential := MachinePrefix + secret
	m := Machine{ID: "m_" + id, Name: e.freeMachineName(r.Name), Envs: envs, CredentialHash: hashToken(credential), CreatedAt: e.now().UTC()}
	if err := e.repo.PutMachine(ctx, m); err != nil {
		return Machine{}, err
	}
	e.apply(func() { e.machines = append(e.machines, m) })
	r.machine, r.credential = &m, credential
	if grace := e.now().Add(approvedGrace); r.ExpiresAt.Before(grace) {
		r.ExpiresAt = grace // approved in its last seconds: the CLI still gets it
	}
	return stripMachine(m), nil
}

// freeMachineName is name, or name-2, name-3… if a live machine has it:
// token names start with the machine's, so two "MacBook-Pro"s would
// otherwise fight over the same worktree names. Callers hold e.wmu.
func (e *Engine) freeMachineName(name string) string {
	taken := func(n string) bool {
		return slices.ContainsFunc(e.machines, func(m Machine) bool { return !m.Revoked() && m.Name == n })
	}
	out := name
	for i := 2; taken(out); i++ {
		out = fmt.Sprintf("%s-%d", name, i)
	}
	return out
}

// DenyLink turns down the machine waiting with this user code.
func (e *Engine) DenyLink(code string) error {
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	i, err := e.takeLink(code)
	if err != nil {
		return err
	}
	e.links.deny(i)
	return nil
}

// DenyLinkRequest turns down a waiting request by its ID, from the list.
func (e *Engine) DenyLinkRequest(id string) error {
	e.links.mu.Lock()
	defer e.links.mu.Unlock()
	e.links.prune(e.now())
	i := slices.IndexFunc(e.links.reqs, func(r *linkRequest) bool { return r.ID == id && r.machine == nil })
	if i < 0 {
		return ErrNotFound
	}
	e.links.deny(i)
	return nil
}

// ownerRevokedLocked reports whether t was issued to a machine that has
// since been revoked. Checked wherever a token is used, so revoking a
// machine stops its tokens at once, even if marking one of them revoked
// failed. Callers hold e.mu or e.wmu.
func (e *Engine) ownerRevokedLocked(t Token) bool {
	id, ok := strings.CutPrefix(t.Principal, "machine:")
	if !ok {
		return false
	}
	i := slices.IndexFunc(e.machines, func(m Machine) bool { return m.ID == id })
	return i >= 0 && e.machines[i].Revoked()
}

func stripMachine(m Machine) Machine {
	m.CredentialHash = ""
	m.Envs = slices.Clone(m.Envs)
	return m
}

// Machines lists linked machines, newest first, without credential hashes.
func (e *Engine) Machines() []Machine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Machine, 0, len(e.machines))
	for _, m := range e.machines {
		out = append(out, stripMachine(m))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RevokeMachine stops a machine and revokes every token it was issued, so
// nothing it got keeps working.
func (e *Engine) RevokeMachine(ctx context.Context, id string) error {
	e.wmu.Lock()
	defer e.wmu.Unlock()
	i := slices.IndexFunc(e.machines, func(m Machine) bool { return m.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	now := e.now().UTC()
	m := e.machines[i]
	if !m.Revoked() {
		m.RevokedAt = &now
		if err := e.repo.PutMachine(ctx, m); err != nil {
			return err
		}
		e.apply(func() { e.machines[i] = m })
	}
	// Also on a second call, so a token whose revoke failed last time is
	// retried.
	for j := range e.tokens {
		t := e.tokens[j]
		if t.Principal != m.Principal() || t.Revoked() {
			continue
		}
		t.RevokedAt = &now
		if err := e.repo.PutToken(ctx, t); err != nil {
			return err
		}
		e.apply(func() { e.tokens[j] = t })
	}
	return nil
}

// machineLocked finds the live machine with this credential. Callers hold
// e.mu or e.wmu.
func (e *Engine) machineLocked(credential string) (int, error) {
	if !strings.HasPrefix(credential, MachinePrefix) {
		return -1, ErrUnknownKey
	}
	h := hashToken(credential)
	i := slices.IndexFunc(e.machines, func(m Machine) bool { return m.CredentialHash == h })
	if i < 0 || e.machines[i].Revoked() {
		return -1, ErrUnknownKey
	}
	return i, nil
}

// Machine returns the live machine with this credential.
func (e *Engine) Machine(credential string) (Machine, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	i, err := e.machineLocked(credential)
	if err != nil {
		return Machine{}, err
	}
	return stripMachine(e.machines[i]), nil
}

// EnsureMachineToken returns the machine's live token called name in envID,
// creating it if needed: `keystub run` on a linked machine keeps one per
// worktree. The token is named "<machine>/<name>", carries principal
// machine:<id>, and may use every service. envID "" means the machine's
// first environment.
func (e *Engine) EnsureMachineToken(ctx context.Context, credential, envID, name string) (string, Token, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", Token{}, errors.New("a token needs a name")
	}
	e.wmu.Lock()
	defer e.wmu.Unlock()
	i, err := e.machineLocked(credential)
	if err != nil {
		return "", Token{}, err
	}
	m := e.machines[i]
	if len(m.Envs) == 0 {
		return "", Token{}, fmt.Errorf("%w: machine %s may use no environment", ErrNotAllowed, m.Name)
	}
	if envID == "" {
		envID = m.Envs[0]
	}
	if !slices.Contains(m.Envs, envID) {
		return "", Token{}, fmt.Errorf("%w: machine %s may use %s, not %s", ErrNotAllowed, m.Name, strings.Join(m.Envs, ", "), envID)
	}
	now := e.now()
	if m.LastSeen == nil || now.Sub(*m.LastSeen) >= lastSeenEvery {
		seen := now.UTC()
		m.LastSeen = &seen
		if err := e.repo.PutMachine(ctx, m); err == nil {
			e.apply(func() { e.machines[i] = m })
		}
	}
	// The token is named "<machine>/<name>", so name gets what's left.
	if room := maxTokenName - len(m.Name) - 1; len(name) > room {
		return "", Token{}, fmt.Errorf("a worktree name on machine %s can be at most %d characters (a token name is at most %d, and starts with %q)", m.Name, room, maxTokenName, m.Name+"/")
	}
	full := m.Name + "/" + name
	live := 0
	for _, t := range e.tokens {
		if t.Principal != m.Principal() || !t.Usable(now) {
			continue
		}
		if t.EnvID == envID && t.Name == full {
			// Used again with under half its life left: it gets a full one,
			// so a run or agent started now doesn't lose it partway.
			if t.ExpiresAt != nil && t.ExpiresAt.Sub(now) < MachineTokenLifetime/2 {
				exp := now.Add(MachineTokenLifetime)
				t.ExpiresAt = &exp
				if err := e.repo.PutToken(ctx, t); err != nil {
					return "", Token{}, err
				}
				j := slices.IndexFunc(e.tokens, func(x Token) bool { return x.ID == t.ID })
				e.apply(func() { e.tokens[j] = t })
			}
			secret, err := e.open(ctx, t.Token)
			return secret, strip(t), err
		}
		live++
	}
	if live >= maxMachineToks {
		return "", Token{}, fmt.Errorf("%w: machine %s already has %d live tokens; revoke some on the dashboard", ErrNotAllowed, m.Name, live)
	}
	return e.create(ctx, TokenSpec{EnvID: envID, Name: full, Principal: m.Principal(), TTL: MachineTokenLifetime})
}
