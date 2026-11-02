package runenv

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestVars(t *testing.T) {
	c := Config{ProxyAddr: "127.0.0.1:8787", Token: "sk-stub-abc", KeyName: "wt", CAPath: "/h/ca.pem", BundlePath: "/h/bundle.pem", EnvVars: []string{"OPENAI_API_KEY", "GH_TOKEN"}}
	env := map[string]string{"NO_PROXY": "corp.internal,localhost"}
	v := Vars(c, func(k string) string { return env[k] })

	if v["HTTPS_PROXY"] != "http://keystub:sk-stub-abc@127.0.0.1:8787" {
		t.Fatalf("HTTPS_PROXY = %q", v["HTTPS_PROXY"])
	}
	if v["OPENAI_API_KEY"] != "sk-stub-abc" || v["GH_TOKEN"] != "sk-stub-abc" {
		t.Fatal("placeholders not set")
	}
	if v["NO_PROXY"] != "corp.internal,localhost,127.0.0.1,::1,.localhost" {
		t.Fatalf("NO_PROXY = %q", v["NO_PROXY"])
	}
	if v["SSL_CERT_FILE"] != "/h/bundle.pem" || v["NODE_EXTRA_CA_CERTS"] != "/h/ca.pem" {
		t.Fatal("CA paths wrong")
	}
}

func TestExportsQuote(t *testing.T) {
	out := Exports(map[string]string{"A": "it's"})
	if strings.TrimSpace(out) != `export A='it'\''s'` {
		t.Fatalf("got %q", out)
	}
}

func TestWriteBundle(t *testing.T) {
	path := t.TempDir() + "/bundle.pem"
	ca := []byte("-----BEGIN CERTIFICATE-----\nkeystub\n-----END CERTIFICATE-----\n")
	if err := WriteBundle(path, ca); err != nil {
		t.Skip("no system roots here:", err)
	}
}

func TestTemplatesBundleAndLowercaseNoProxy(t *testing.T) {
	c := Config{ProxyAddr: "127.0.0.1:8787", Token: "sk-stub-abc", EnvVars: []string{"CONVEX_DEPLOY_KEY=prod:my-app|{key}"}}
	env := map[string]string{"no_proxy": "corp.internal"}
	v := Vars(c, func(k string) string { return env[k] })
	if v["CONVEX_DEPLOY_KEY"] != "prod:my-app|sk-stub-abc" {
		t.Fatalf("template: %q", v["CONVEX_DEPLOY_KEY"])
	}
	if _, ok := v["SSL_CERT_FILE"]; ok {
		t.Fatal("SSL_CERT_FILE set without a bundle")
	}
	if !strings.HasPrefix(v["no_proxy"], "corp.internal,") {
		t.Fatalf("lowercase no_proxy lost: %q", v["no_proxy"])
	}
}

func TestCompactTemplate(t *testing.T) {
	v := Vars(Config{Token: "sk-stub-abc123", EnvVars: []string{"VERCEL_TOKEN={key_compact}"}}, func(string) string { return "" })
	if v["VERCEL_TOKEN"] != "skstubabc123" {
		t.Fatalf("VERCEL_TOKEN = %q", v["VERCEL_TOKEN"])
	}
}

func TestDirectVarsHaveNoProxy(t *testing.T) {
	v := Vars(Config{
		Token: "sk-stub-ab", KeyName: "wt", EnvID: "default/dev", EnvVars: []string{"OPENAI_API_KEY"},
		Direct: true, EdgeURL: "http://127.0.0.1:8789/", BaseURLs: []string{"OPENAI_BASE_URL=/s/openai/v1"},
	}, func(string) string { return "" })
	if v["OPENAI_BASE_URL"] != "http://127.0.0.1:8789/s/openai/v1" || v["OPENAI_API_KEY"] != "sk-stub-ab" {
		t.Fatalf("vars = %v", v)
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"} {
		if _, ok := v[k]; ok {
			t.Errorf("direct mode set %s", k)
		}
	}
}

func TestWriteBundleNeverShowsHalfAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca-bundle.pem")
	pems := [][]byte{[]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")}
	if err := WriteBundle(path, pems[0]); err != nil {
		t.Skip("no system roots here:", err)
	}
	full, _ := os.ReadFile(path)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = WriteBundle(path, pems[i%2])
				}
			}
		}()
	}
	for range 200 {
		b, err := os.ReadFile(path)
		if err != nil || len(b) != len(full) {
			close(stop)
			wg.Wait()
			t.Fatalf("read %d of %d bytes, %v", len(b), len(full), err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestExportsNeverRunsAName(t *testing.T) {
	out := Exports(map[string]string{"$(touch /tmp/pwn)_KEY": "x", "`id`_URL": "y", "OK_KEY": "z"})
	if out != "export OK_KEY='z'\n" {
		t.Fatalf("got %q", out)
	}
}
