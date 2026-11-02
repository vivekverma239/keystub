package ca

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLeafVerifiesAgainstCA(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.openai.com", "127.0.0.1"} {
		l, err := c.Leaf(host)
		if err != nil {
			t.Fatal(err)
		}
		_, err = l.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: c.Pool()})
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}

	// Reloading reads the same CA rather than making a new one.
	c2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(c2.CertPEM()) != string(c.CertPEM()) {
		t.Fatal("CA changed on reload")
	}

	a, _ := c.Leaf("api.github.com")
	b, _ := c.Leaf("api.github.com")
	if a != b {
		t.Fatal("leaf not cached")
	}
}

func TestParallelStartsShareOneCA(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	cas := make([]*CA, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() { defer wg.Done(); cas[i], errs[i] = LoadOrCreate(dir) }()
	}
	wg.Wait()
	onDisk, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("start %d: %v", i, errs[i])
		}
		if !bytes.Equal(cas[i].CertPEM(), onDisk.CertPEM()) {
			t.Fatalf("start %d signs with a CA that isn't the one on disk", i)
		}
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestLeftoverKeyIsReplaced(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	// ca.pem deleted to start again, leaving an old key behind.
	if err := os.Remove(filepath.Join(dir, "ca.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("a leftover key blocks the CA: %v", err)
	}
}

// Parallel starts that all find a leftover key agree on one new pair.
func TestParallelStartsReplaceALeftoverKeyOnce(t *testing.T) {
	for range 20 {
		dir := t.TempDir()
		if _, err := LoadOrCreate(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "ca.pem")); err != nil {
			t.Fatal(err)
		}
		const n = 6
		cas := make([]*CA, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() { defer wg.Done(); cas[i], errs[i] = LoadOrCreate(dir) }()
		}
		wg.Wait()
		onDisk, err := LoadOrCreate(dir)
		if err != nil {
			t.Fatal(err)
		}
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("start %d: %v", i, errs[i])
			}
			if !bytes.Equal(cas[i].CertPEM(), onDisk.CertPEM()) {
				t.Fatalf("start %d signs with a CA that isn't the one on disk", i)
			}
		}
	}
}

func TestLeafCacheIsBounded(t *testing.T) {
	old := maxLeaves
	maxLeaves = 8
	defer func() { maxLeaves = old }()
	c, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := c.Leaf(fmt.Sprintf("h%d.twilio.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(c.cache); n > 8 {
		t.Fatalf("cache holds %d leaves", n)
	}
}
