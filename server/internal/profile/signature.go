package profile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"slices"
)

// Verification outcomes for a profile file and its detached `.sig`.
const (
	SigValid     = "valid"
	SigInvalid   = "invalid"
	SigUnsigned  = "unsigned"
	SigUntrusted = "untrusted"
)

type signatureFile struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

// VerifyResult describes a signature check.
type VerifyResult struct {
	Status string
	KeyID  string
}

// Verify checks `<path>.sig` against the exact bytes of the profile file. trusted lists
// base64 ed25519 public keys; an empty list means "any valid signature is acceptable".
func Verify(path string, data []byte, trusted []string) VerifyResult {
	raw, err := os.ReadFile(path + ".sig") //nolint:gosec // sits next to an operator-chosen profile
	if errors.Is(err, os.ErrNotExist) {
		return VerifyResult{Status: SigUnsigned}
	}
	if err != nil {
		return VerifyResult{Status: SigInvalid}
	}
	return VerifyBytes(data, raw, trusted)
}

// VerifyBytes checks a signature document against profile bytes.
func VerifyBytes(data, sigDoc []byte, trusted []string) VerifyResult {
	var sig signatureFile
	if err := json.Unmarshal(sigDoc, &sig); err != nil || sig.Algorithm != "ed25519" {
		return VerifyResult{Status: SigInvalid}
	}
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return VerifyResult{Status: SigInvalid}
	}
	s, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), data, s) {
		return VerifyResult{Status: SigInvalid, KeyID: sig.KeyID}
	}
	if len(trusted) > 0 && !slices.Contains(trusted, sig.PublicKey) {
		return VerifyResult{Status: SigUntrusted, KeyID: sig.KeyID}
	}
	return VerifyResult{Status: SigValid, KeyID: sig.KeyID}
}
