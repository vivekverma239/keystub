package core

import "context"

// The ports below are everything core needs from the outside world. Each
// hosting target picks one adapter per port:
//
//	laptop      jsonfile  + keychain sealer + memory limiter + file log
//	server      sqlite    + KMS sealer      + memory limiter + stdout log
//	Kubernetes  postgres  + KMS sealer      + redis limiter  + otel log
//
// Adapters live outside core and are chosen by name at start-up.

// Repository stores the model. Values it holds are already sealed; a
// repository never sees a real key.
type Repository interface {
	ListProjects(ctx context.Context) ([]Project, error)
	PutProject(ctx context.Context, p Project) error

	ListEnvironments(ctx context.Context) ([]Environment, error)
	PutEnvironment(ctx context.Context, e Environment) error
	DeleteEnvironment(ctx context.Context, id string) error

	ListServices(ctx context.Context) ([]Service, error)
	PutService(ctx context.Context, s Service) error
	DeleteService(ctx context.Context, id string) error

	ListKeys(ctx context.Context) ([]SavedKey, error)
	PutKey(ctx context.Context, k SavedKey) error
	DeleteKey(ctx context.Context, id string) error

	ListLinks(ctx context.Context) ([]Link, error)
	PutLink(ctx context.Context, l Link) error // one per (EnvID, ServiceID)
	DeleteLink(ctx context.Context, envID, serviceID string) error

	ListTokens(ctx context.Context) ([]Token, error)
	PutToken(ctx context.Context, t Token) error

	ListMachines(ctx context.Context) ([]Machine, error)
	PutMachine(ctx context.Context, m Machine) error
}

// Sealer encrypts and decrypts values. The envelope sealer holds a master
// key (from a file, the OS keychain or an env var); a KMS sealer would ask
// the cloud to do it.
type Sealer interface {
	// Name is stored with each sealed value.
	Name() string
	Seal(ctx context.Context, plaintext []byte) (Sealed, error)
	Open(ctx context.Context, v Sealed) ([]byte, error)
}

// Scope is one level a request counts against: a project, an environment,
// a token or a saved key, with that level's limits.
type Scope struct {
	Key    string // e.g. "project:my-app", "token:tk_123", "key:key_ab12"
	Label  string // for messages, e.g. "token ci-agent"
	Limits Limits
}

// Limiter counts requests per scope. A shared limiter (Redis, Postgres)
// lets several proxies enforce one limit.
type Limiter interface {
	// Allow checks every scope and, only if all have room, counts the
	// request against all of them. It returns a *LimitError naming the
	// first scope that is full.
	Allow(ctx context.Context, scopes []Scope) error
	// UsedToday returns today's count for a scope key.
	UsedToday(ctx context.Context, key string) (int, error)
}

// Sink records proxied requests.
type Sink interface {
	Add(e Entry)
}

// LogReader returns recent entries, newest first, for the dashboard.
type LogReader interface {
	Recent(n int) []Entry
}
