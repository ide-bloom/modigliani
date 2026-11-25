package profile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

const minimal = `{"schema_version": 1, "id": "x", "name": "X", "revivability": {"status": "revivable"},
 "handlers": {"http": [{"id": "a", "method": "GET", "path": "/a/{id}", "response": {"status": 200, "body": {"k": "{{req.path.id}}"}}}]},
 "provenance": {"generated_by": "t", "created": "now"}}`

func TestParseJSONAndYAML(t *testing.T) {
	p, err := Parse([]byte(minimal), "x.json")
	if err != nil {
		t.Fatal(err)
	}
	if p.Handlers.HTTP[0].Path != "/a/{id}" {
		t.Errorf("path %q", p.Handlers.HTTP[0].Path)
	}
	y, err := Parse([]byte("schema_version: 1\nid: y\nname: Y\nrevivability: {status: revivable}\nprovenance: {generated_by: t, created: now}\n"), "y.yaml")
	if err != nil || y.ID != "y" {
		t.Fatalf("yaml: %v %v", y, err)
	}
	if _, err := Parse([]byte(`{"schema_version": 2, "id": "z"}`), "z.json"); err == nil {
		t.Error("schema version 2 must be rejected")
	}
}

func TestLibraryProfilesParse(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "profiles", "library", "*.yaml"))
	if len(files) < 3 {
		t.Fatalf("expected library profiles, found %v", files)
	}
	// The published maintainer key (server config example) must be the one that signed them.
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		TrustedKeys []string `yaml:"trusted_keys"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil || len(cfg.TrustedKeys) == 0 {
		t.Fatalf("config.example.yaml must list the library key: %v", err)
	}
	trusted := cfg.TrustedKeys
	for _, f := range files {
		p, data, err := LoadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !p.Provenance.Scrubbed {
			t.Errorf("%s is not scrubbed", f)
		}
		if v := Verify(f, data, trusted); v.Status != SigValid {
			t.Errorf("%s signature %s", f, v.Status)
		}
	}
}

func TestTemplatesAndPatterns(t *testing.T) {
	params, ok := MatchTemplate("thermo/{id}/cmd", "thermo/T1/cmd", "/")
	if !ok || params["id"] != "T1" {
		t.Errorf("match %v %v", params, ok)
	}
	if _, ok := MatchTemplate("a/{id}", "a/b/c", "/"); ok {
		t.Error("segment counts differ")
	}
	if _, ok := MatchTemplate("a/{id}", "a/", "/"); ok {
		t.Error("empty parameters do not match")
	}
	topic, ok := FillTemplate("thermo/{id}/cmd", "/", map[string]string{"id": "T1"})
	if !ok || topic != "thermo/T1/cmd" {
		t.Errorf("fill %q", topic)
	}
	vars, ok := MatchPattern("thermo-{device_id}", "thermo-TH-1")
	if !ok || vars["device_id"] != "TH-1" {
		t.Errorf("pattern %v", vars)
	}
	if _, ok := MatchPattern("thermo-{device_id}", "other-1"); ok {
		t.Error("pattern must anchor")
	}
}

func TestSignatures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	data := []byte(minimal)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if Verify(path, data, nil).Status != SigUnsigned {
		t.Error("unsigned")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	sig, _ := json.Marshal(map[string]string{"algorithm": "ed25519", "key_id": "k", "public_key": pubB64,
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))})
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if v := Verify(path, data, nil); v.Status != SigValid || v.KeyID != "k" {
		t.Errorf("valid: %v", v)
	}
	if Verify(path, data, []string{pubB64}).Status != SigValid {
		t.Error("trusted")
	}
	if Verify(path, data, []string{"someone-else"}).Status != SigUntrusted {
		t.Error("untrusted")
	}
	if Verify(path, append(data, ' '), nil).Status != SigInvalid {
		t.Error("tampered")
	}
}
