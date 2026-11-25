package engine

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"

	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// jwtShaped builds a token with the structure of a JWT (header.payload.signature) so devices
// that parse `exp` keep working. Devices cannot verify the vendor's signature without the
// vendor's key, so the signature part is random: the vendor's secret is never needed.
func jwtShaped(now time.Time, lifetime int) string {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"iat": now.Unix(), "exp": now.Unix() + int64(lifetime), "jti": tmpl.NewUUID()})
	sig := make([]byte, 32)
	_, _ = rand.Read(sig)
	return strings.Join([]string{enc.EncodeToString(header), enc.EncodeToString(payload), enc.EncodeToString(sig)}, ".")
}

func numeric(n int) string {
	var sb strings.Builder
	for range n {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			d = big.NewInt(0)
		}
		sb.WriteByte("0123456789"[d.Int64()])
	}
	return sb.String()
}
