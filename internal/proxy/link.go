package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
)

// Linker is what the edge needs from the core to link machines and hand
// them tokens. *core.Engine provides it.
type Linker interface {
	StartLink(name, from string) (core.LinkStart, error)
	PollLink(deviceCode string) (core.Machine, string, error)
	EnsureMachineToken(ctx context.Context, credential, envID, name string) (string, core.Token, error)
}

// LinkStartResponse is the body of POST /link.
type LinkStartResponse struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
	ExpiresIn  int    `json:"expiresIn"` // seconds
	Interval   int    `json:"interval"`  // seconds between polls
}

// LinkedMachine is the machine in a successful POST /link/poll.
type LinkedMachine struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Envs []string `json:"envs"`
}

// LinkPollResponse is the body of a successful POST /link/poll. The
// credential is sent once.
type LinkPollResponse struct {
	Machine    LinkedMachine `json:"machine"`
	Credential string        `json:"credential"`
}

// MachineTokenResponse is the body of POST /machine/tokens.
type MachineTokenResponse struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Env       string     `json:"env"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
	Token     string     `json:"token"`
}

// link serves the machine-linking routes, or reports that path isn't one.
func (e *Edge) link(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/link", "/link/poll", "/machine/tokens":
	default:
		return false
	}
	if e.Link == nil {
		jsonError(w, http.StatusNotFound, "keystub: this server doesn't link machines")
		return true
	}
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "keystub: use POST "+r.URL.Path)
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	switch r.URL.Path {
	case "/link":
		var in struct {
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jsonError(w, http.StatusBadRequest, `keystub: body must be {"name": "…"}`)
			return true
		}
		st, err := e.Link.StartLink(in.Name, e.clientIP(r))
		if errors.Is(err, core.ErrTooManyLinks) {
			jsonError(w, http.StatusTooManyRequests, "keystub: "+err.Error())
			return true
		}
		if err != nil {
			jsonError(w, http.StatusBadRequest, "keystub: "+err.Error())
			return true
		}
		writeJSON(w, LinkStartResponse{DeviceCode: st.DeviceCode, UserCode: st.UserCode,
			ExpiresIn: int(time.Until(st.ExpiresAt).Seconds()), Interval: int(core.LinkInterval / time.Second)})
	case "/link/poll":
		var in struct {
			DeviceCode string `json:"deviceCode"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.DeviceCode == "" {
			jsonError(w, http.StatusBadRequest, `keystub: body must be {"deviceCode": "…"}`)
			return true
		}
		m, cred, err := e.Link.PollLink(in.DeviceCode)
		switch {
		case errors.Is(err, core.ErrLinkPending):
			jsonError(w, http.StatusAccepted, "keystub: "+err.Error())
		case errors.Is(err, core.ErrLinkDenied):
			jsonError(w, http.StatusForbidden, "keystub: "+err.Error())
		case err != nil:
			jsonError(w, http.StatusNotFound, "keystub: "+core.ErrLinkExpired.Error())
		default:
			writeJSON(w, LinkPollResponse{Machine: LinkedMachine{ID: m.ID, Name: m.Name, Envs: m.Envs}, Credential: cred})
		}
	case "/machine/tokens":
		cred, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var in struct {
			Env  string `json:"env"`
			Name string `json:"name"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			jsonError(w, http.StatusBadRequest, `keystub: body must be {"env": "project/env", "name": "…"}`)
			return true
		}
		secret, t, err := e.Link.EnsureMachineToken(r.Context(), strings.TrimSpace(cred), in.Env, in.Name)
		switch {
		case errors.Is(err, core.ErrUnknownKey):
			jsonError(w, http.StatusUnauthorized, "keystub: this machine isn't linked, or was revoked; run keystub link again")
		case errors.Is(err, core.ErrNotAllowed), errors.Is(err, core.ErrNameTaken):
			jsonError(w, http.StatusForbidden, "keystub: "+err.Error())
		case err != nil:
			jsonError(w, http.StatusBadRequest, "keystub: "+err.Error())
		default:
			writeJSON(w, MachineTokenResponse{ID: t.ID, Name: t.Name, Env: t.EnvID, ExpiresAt: t.ExpiresAt, Token: secret})
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

var (
	badIPHeader sync.Once
	headerName  = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
)

// CheckClientIPHeader refuses a --client-ip-header that never holds a
// bare address: with it, every request would share the proxy's.
func CheckClientIPHeader(name string) error {
	switch {
	case name == "":
		return nil
	case strings.EqualFold(name, "Forwarded"):
		return errors.New("--client-ip-header: Forwarded holds for=… pairs, not an address; use a header such as X-Real-IP or CF-Connecting-IP")
	case !headerName.MatchString(name):
		return fmt.Errorf("--client-ip-header: %q isn't a header name", name)
	}
	return nil
}

// clientIP is the address a /link request came from: the trusted proxy's
// header if set (the last address in it, the one that proxy added), else
// the connection's.
func (e *Edge) clientIP(r *http.Request) string {
	if e.ClientIPHeader != "" {
		if v := r.Header.Values(e.ClientIPHeader); len(v) > 0 {
			parts := strings.Split(v[len(v)-1], ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if h, _, err := net.SplitHostPort(last); err == nil {
				last = h // "1.2.3.4:5678", "[2001:db8::1]:443"
			}
			if ip := net.ParseIP(strings.Trim(last, "[]")); ip != nil {
				return ip.String()
			}
			badIPHeader.Do(func() {
				log.Printf("keystub: the %s header holds no address (%q); counting link requests by the connection's", e.ClientIPHeader, v[len(v)-1])
			})
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
