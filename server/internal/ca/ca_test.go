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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func TestIssueOnlyAllowedNames(t *testing.T) {
	cert, key := newCA(t)
	a := New(cert, key)
	a.Allow("api.vendor.example", "10.0.0.5")
	c, err := a.Issue("API.vendor.example.")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: "api.vendor.example", Roots: pool}); err != nil {
		t.Errorf("leaf does not verify: %v", err)
	}
	again, _ := a.Issue("api.vendor.example")
	if again != c {
		t.Error("certificates are cached")
	}
	if ip, err := a.Issue("10.0.0.5"); err != nil || !ip.Leaf.IPAddresses[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("ip cert: %v", err)
	}
	if _, err := a.Issue("bank.example"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("unlisted names must be refused, got %v", err)
	}
}

func TestTLSHandshakeBySNI(t *testing.T) {
	cert, key := newCA(t)
	a := New(cert, key)
	a.Allow("api.vendor.example")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", a.TLSConfig("api.vendor.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "api.vendor.example", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("device accepting the local CA must connect: %v", err)
	}
	_ = conn.Close()
	if _, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "api.vendor.example", MinVersion: tls.VersionTLS12}); err == nil {
		t.Error("a strictly verifying device must reject the local CA")
	}
}

func TestLoadPlainKey(t *testing.T) {
	cert, key := newCA(t)
	dir := t.TempDir()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(filepath.Join(dir, CertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600)
	_ = os.WriteFile(filepath.Join(dir, KeyFilePlain), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Certificate().Subject.CommonName != "Test CA" {
		t.Error("wrong CA")
	}
	if _, err := Load(t.TempDir()); err == nil {
		t.Error("missing CA must fail")
	}
}
