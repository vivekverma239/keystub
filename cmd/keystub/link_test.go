package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vivekverma239/keystub/internal/core"
	"github.com/vivekverma239/keystub/internal/coretest"
	"github.com/vivekverma239/keystub/internal/proxy"
	"github.com/vivekverma239/keystub/internal/reqlog"
	"github.com/vivekverma239/keystub/internal/runenv"
)

// linkedBox links a machine to an edge served from e and writes its
// machine.json into a fresh KEYSTUB_HOME, credential in the file.
func linkedBox(t *testing.T) (*core.Engine, *httptest.Server, string) {
	t.Helper()
	t.Setenv("KEYSTUB_SECRETS", "file")
	e, _ := coretest.Engine(t, "")
	l, _ := reqlog.Open("", 5)
	ed := proxy.NewEdge(e, l)
	ed.Link = e
	srv := httptest.NewServer(ed)
	t.Cleanup(srv.Close)

	st, err := e.StartLink("box", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ApproveLink(context.Background(), st.UserCode, []string{core.DefaultEnv}); err != nil {
		t.Fatal(err)
	}
	m, cred, err := e.PollLink(st.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("KEYSTUB_HOME", home)
	writeInfo(t, filepath.Join(home, "machine.json"), machineInfo{Server: srv.URL, ID: m.ID, Name: m.Name, Envs: m.Envs, Credential: cred})
	return e, srv, home
}

func TestRunOnALinkedMachine(t *testing.T) {
	e, srv, _ := linkedBox(t)
	var o runOpts
	if err := o.fromMachine(); err != nil {
		t.Fatal(err)
	}
	if o.remote != srv.URL || e.CheckToken(o.token) != nil {
		t.Fatalf("opts = %+v", o)
	}
	toks := e.Tokens(core.DefaultEnv)
	if len(toks) != 1 || toks[0].Principal == "" || toks[0].Name != "box/"+runenv.DefaultKeyName() {
		t.Fatalf("tokens = %+v", toks)
	}
	// An explicit token wins over the link.
	o = runOpts{token: tok}
	if err := o.fromMachine(); err != nil || o.token != tok || o.remote != "" {
		t.Fatalf("explicit token: %+v %v", o, err)
	}
}

func TestRevokedMachineGetsNoToken(t *testing.T) {
	e, _, _ := linkedBox(t)
	if err := e.RevokeMachine(context.Background(), e.Machines()[0].ID); err != nil {
		t.Fatal(err)
	}
	var o runOpts
	if err := o.fromMachine(); err == nil {
		t.Fatalf("a revoked machine got %+v", o)
	}
}

func TestUnlinkForgetsTheMachine(t *testing.T) {
	_, _, home := linkedBox(t)
	if err := unlinkCmd(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, "machine.json")); !os.IsNotExist(err) {
		t.Fatalf("machine.json still there: %v", err)
	}
	if mi, _, err := linkedMachine(home); mi != nil || err != nil {
		t.Fatalf("still linked: %+v %v", mi, err)
	}
}

func TestAnotherRemoteGetsNoMachineToken(t *testing.T) {
	e, srv, _ := linkedBox(t)
	o := runOpts{remote: "https://other.example.com"}
	if err := o.fromMachine(); err != nil {
		t.Fatal(err)
	}
	if o.token != "" || len(e.Tokens(core.DefaultEnv)) != 0 {
		t.Fatalf("the linked server's token went to another remote: %+v", o)
	}
	o = runOpts{remote: srv.URL + "/"}
	if err := o.fromMachine(); err != nil || o.token == "" {
		t.Fatalf("the linked server itself: %+v %v", o, err)
	}
}

func TestLinkRefusesWhenAlreadyLinked(t *testing.T) {
	_, srv, _ := linkedBox(t)
	if err := linkCmd([]string{srv.URL}); err == nil || !strings.Contains(err.Error(), "already linked") {
		t.Fatalf("got %v", err)
	}
}

func TestSameServer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://e.example", "https://E.example/", true},
		{"https://e.example:443", "https://e.example", true},
		{"http://127.0.0.1:8789", "http://127.0.0.1:8789/", true},
		{"https://e.example/keystub", "https://e.example/keystub/", true},
		{"https://e.example", "https://other.example", false},
		{"https://e.example:8443", "https://e.example", false},
		{"http://e.example", "https://e.example", false},
		{"https://e.example/a", "https://e.example/b", false},
	} {
		if got := sameServer(c.a, c.b); got != c.same {
			t.Errorf("%s vs %s: %v", c.a, c.b, got)
		}
	}
	// A differently written --remote for the linked server still gets its token.
	_, srv, _ := linkedBox(t)
	o := runOpts{remote: "HTTP" + strings.TrimPrefix(srv.URL, "http") + "/"}
	if err := o.fromMachine(); err != nil || o.token == "" {
		t.Fatalf("%+v %v", o, err)
	}
}

func TestPollOutlastsTheServer(t *testing.T) {
	start := time.Now()
	// The server keeps an approval made in the request's last seconds for
	// a minute: the CLI must still be polling then.
	if d := pollDeadline(start, int(core.LinkLifetime/time.Second)); !d.After(start.Add(core.LinkLifetime + time.Minute)) {
		t.Fatalf("gives up at %v", d.Sub(start))
	}
}
