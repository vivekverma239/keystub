package agent

import (
	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/proxy"
)

// Hosts is what one token's proxy decrypts, by the agent's rules, for a
// proxy that serves many tokens (keystub gateway): of the services a
// server lists, only hosts Keystub's built-in catalog gives that same
// service. No host is allowed beyond the catalog, so a server can't have
// a shared proxy decrypt anything else.
type Hosts struct{ h *hosts }

// NewHosts returns an empty catalog: nothing is decrypted until Set.
func NewHosts() *Hosts { return &Hosts{h: &hosts{trusted: trustedHosts(nil)}} }

// Set checks cat as FetchCatalog does and keeps, of each service, the
// hosts the built-in catalog gives it. It returns the catalog as served
// and the hosts it ignored.
func (h *Hosts) Set(cat proxy.CatalogResponse) (proxy.CatalogResponse, []string) {
	return h.h.set(clean(cat))
}

// ServiceForHost implements proxy.Catalog.
func (h *Hosts) ServiceForHost(host string) (core.Service, bool) { return h.h.ServiceForHost(host) }
