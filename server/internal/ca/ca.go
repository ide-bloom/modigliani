// Package ca loads the local CA created by `modigliani ca init` and issues server
// certificates for the hostnames that loaded profiles answer — and for nothing else.
package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

// File names shared with studio/src/modigliani/ca.py.
const (
	CertFile     = "ca.crt"
	KeyFilePlain = "ca.key"
	KeyFileDPAPI = "ca.key.dpapi"
)

// ErrNotAllowed is returned for SNI names that no loaded profile answers.
var ErrNotAllowed = errors.New("hostname is not served by any loaded profile")

// Authority issues and caches leaf certificates.
type Authority struct {
	cert    *x509.Certificate
	key     crypto.Signer
	mu      sync.Mutex
	cache   map[string]*tls.Certificate
	allowed map[string]bool
	now     func() time.Time
}

// Load reads the CA certificate and its (DPAPI-protected or owner-only) private key.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile)) //nolint:gosec // operator-configured directory
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w (run `modigliani ca init`)", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("CA certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	var der []byte
	if blob, err := os.ReadFile(filepath.Join(dir, KeyFileDPAPI)); err == nil { //nolint:gosec // see above
		if der, err = unprotect(blob); err != nil {
			return nil, fmt.Errorf("decrypt CA key with DPAPI: %w", err)
		}
	} else if keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFilePlain)); err == nil { //nolint:gosec // see above
		kb, _ := pem.Decode(keyPEM)
		if kb == nil {
			return nil, errors.New("CA key is not PEM")
		}
		der = kb.Bytes
	} else {
		return nil, fmt.Errorf("no CA key in %s", dir)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key cannot sign")
	}
	return New(cert, signer), nil
}

// New wraps an existing CA certificate and key.
func New(cert *x509.Certificate, key crypto.Signer) *Authority {
	return &Authority{cert: cert, key: key, cache: map[string]*tls.Certificate{}, allowed: map[string]bool{}, now: time.Now}
}

// Allow adds hostnames that may receive certificates.
func (a *Authority) Allow(names ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, n := range names {
		a.allowed[strings.ToLower(strings.TrimSuffix(n, "."))] = true
	}
}

// Certificate returns the CA certificate.
func (a *Authority) Certificate() *x509.Certificate { return a.cert }

// Issue returns a (cached) leaf certificate for an allowed hostname.
func (a *Authority) Issue(name string) (*tls.Certificate, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowed[name] {
		return nil, fmt.Errorf("%w: %q", ErrNotAllowed, name)
	}
	if c, ok := a.cache[name]; ok && c.Leaf != nil && a.now().Before(c.Leaf.NotAfter.Add(-24*time.Hour)) {
		return c, nil
	}
	// RSA for compatibility with small embedded TLS stacks, as in the Studio CA.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    a.now().Add(-time.Hour),
		NotAfter:     a.now().Add(397 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key, Leaf: leaf}
	a.cache[name] = c
	return c, nil
}

// TLSConfig serves certificates chosen by SNI. Devices that send no SNI get the
// certificate of the fallback name (the first TLS hostname of the loaded profiles).
func (a *Authority) TLSConfig(fallback string) *tls.Config {
	// Old devices speak old TLS. The server only answers enrolled devices, with certificates
	// for the hostnames their profiles name, so a low floor does not widen exposure.
	return &tls.Config{ //nolint:gosec // see above
		MinVersion: tls.VersionTLS10,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = fallback
			}
			return a.Issue(name)
		},
	}
}
