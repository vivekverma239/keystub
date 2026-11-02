// Package ca is Keystub's local certificate authority. It signs a short-lived
// certificate for each host the proxy intercepts.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const leafLife = 24 * time.Hour

// maxLeaves bounds the leaf cache: a wildcard service host
// (*.twilio.com) would otherwise let a client fill memory with a new
// certificate per made-up name.
var maxLeaves = 1024

// CA signs leaf certificates. It is safe for concurrent use.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu    sync.Mutex
	cache map[string]*tls.Certificate
	now   func() time.Time
}

// LoadOrCreate reads ca.pem and ca-key.pem from dir, creating them if
// missing. Several processes may start at once on a fresh dir (parallel
// `keystub run --remote` jobs): creating takes a lock, so one process
// writes the pair and the others then load it, and every process signs
// with the CA its clients trust.
func LoadOrCreate(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if c, err := load(certPath, keyPath); err == nil {
		return c, nil
	}
	// Missing, or caught between another process's key and certificate:
	// read again under the lock.
	unlock, err := lock(filepath.Join(dir, "ca.lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if c, err := load(certPath, keyPath); !errors.Is(err, os.ErrNotExist) {
		return c, err // another process created it while this one waited
	}
	// No one else is writing, so a key without a certificate is left over
	// (a crash between the two, or ca.pem deleted to start again).
	if err := create(certPath, keyPath); err != nil {
		return nil, err
	}
	return load(certPath, keyPath)
}

func load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	c, err := Parse(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w in %s", err, filepath.Dir(certPath))
	}
	return c, nil
}

// Parse makes a CA from a PEM certificate and its PEM private key: an
// ECDSA key, as "EC PRIVATE KEY" (what LoadOrCreate writes) or PKCS #8
// "PRIVATE KEY" (what the hosted edge hands the gateway for an account).
// It refuses a key that isn't the certificate's, or a certificate that
// isn't a CA's.
func Parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("ca: bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("ca: the certificate isn't a CA's")
	}
	var key *ecdsa.PrivateKey
	switch kb.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		var k any
		if k, err = x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
			var ok bool
			if key, ok = k.(*ecdsa.PrivateKey); !ok {
				err = errors.New("ca: the key isn't an ECDSA key")
			}
		}
	default:
		err = errors.New("ca: bad PEM")
	}
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("ca: the key doesn't match the certificate")
	}
	return &CA{cert: cert, key: key, certPEM: pem.EncodeToMemory(cb), cache: map[string]*tls.Certificate{}, now: time.Now}, nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func create(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "Keystub local CA (" + host + ")", Organization: []string{"Keystub"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	// Each file is written whole under a temporary name and renamed into
	// place, the key first: a reader that sees a new key and no (or the
	// old) certificate waits for the lock and reads again.
	tmpKey, err := writeTemp(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmpKey)
	tmpCert, err := writeTemp(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(tmpCert)
	if err := os.Rename(tmpKey, keyPath); err != nil {
		return err
	}
	return os.Rename(tmpCert, certPath)
}

func writeTemp(path string, b []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), mode)
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// CertPEM is the CA certificate that clients must trust.
func (c *CA) CertPEM() []byte { return c.certPEM }

// Pool returns a cert pool holding only this CA.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// Leaf returns a certificate for host, reusing a cached one until it is
// within an hour of expiry.
func (c *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("ca: empty host")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.cache[host]; ok && c.now().Add(time.Hour).Before(l.Leaf.NotAfter) {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	if len(c.cache) >= maxLeaves {
		for h, old := range c.cache {
			if !c.now().Add(time.Hour).Before(old.Leaf.NotAfter) {
				delete(c.cache, h)
			}
		}
		for h := range c.cache {
			if len(c.cache) < maxLeaves {
				break
			}
			delete(c.cache, h) // any: it's signed again when asked for
		}
	}
	c.cache[host] = l
	return l, nil
}
