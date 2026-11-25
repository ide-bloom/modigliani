// Package tmpl renders profile response templates.
//
// A template is any JSON value. Strings may contain `{{ expr }}`; a string that is exactly
// one expression is replaced by the expression's value with its JSON type, otherwise the
// value is interpolated as text. Expressions are dotted paths under these roots:
//
//	req.path.X req.query.X req.header.X req.body.<path> req.topic.X req.payload.<path> req.fields.X
//	device.key device.vars.X  state.X  desired.X  cmd.value cmd.name cmd.seq cmd.id
//	token.value token.expires_in token.expires_at  ph.X
//	now.unix now.unix_ms now.iso  gen.uuid gen.seq gen.hex.N gen.alnum.N
package tmpl

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var exprRe = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

// Context holds everything an expression may refer to.
type Context struct {
	Req     map[string]any
	Device  map[string]any
	State   map[string]any
	Desired map[string]any
	Cmd     map[string]any
	Token   map[string]any
	Ph      map[string]any
	Now     time.Time
	// Seq returns the next value of a per-device counter (gen.seq).
	Seq func() int64
}

// Render evaluates a template value.
func Render(t any, ctx *Context) any {
	switch v := t.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = Render(val, ctx)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			out[i] = Render(val, ctx)
		}
		return out
	case string:
		return renderString(v, ctx)
	default:
		return v
	}
}

func renderString(s string, ctx *Context) any {
	if !strings.Contains(s, "{{") {
		return s
	}
	if m := exprRe.FindStringSubmatchIndex(s); m != nil && m[0] == 0 && m[1] == len(s) {
		v, _ := Lookup(s[m[2]:m[3]], ctx)
		return v
	}
	return exprRe.ReplaceAllStringFunc(s, func(match string) string {
		expr := exprRe.FindStringSubmatch(match)[1]
		v, ok := Lookup(expr, ctx)
		if !ok || v == nil {
			return ""
		}
		return Text(v)
	})
}

// Text formats a value for string interpolation.
func Text(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool, int, int64:
		return fmt.Sprint(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

// Lookup evaluates one expression.
func Lookup(expr string, ctx *Context) (any, bool) {
	parts := strings.Split(strings.TrimSpace(expr), ".")
	if len(parts) == 0 {
		return nil, false
	}
	rest := parts[1:]
	switch parts[0] {
	case "req":
		return path(ctx.Req, rest)
	case "device":
		return path(ctx.Device, rest)
	case "state":
		return path(ctx.State, rest)
	case "desired":
		return path(ctx.Desired, rest)
	case "cmd":
		return path(ctx.Cmd, rest)
	case "token":
		return path(ctx.Token, rest)
	case "ph":
		return path(ctx.Ph, rest)
	case "now":
		return now(ctx.Now, rest)
	case "gen":
		return gen(ctx, rest)
	}
	return nil, false
}

func path(root any, segs []string) (any, bool) {
	cur := root
	for _, s := range segs {
		switch c := cur.(type) {
		case map[string]any:
			v, ok := c[s]
			if !ok {
				return nil, false
			}
			cur = v
		case map[string]string:
			v, ok := c[s]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(s)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func now(t time.Time, rest []string) (any, bool) {
	if t.IsZero() {
		t = time.Now()
	}
	if len(rest) != 1 {
		return nil, false
	}
	switch rest[0] {
	case "unix":
		return float64(t.Unix()), true
	case "unix_ms":
		return float64(t.UnixMilli()), true
	case "iso":
		return t.UTC().Format(time.RFC3339), true
	}
	return nil, false
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func gen(ctx *Context, rest []string) (any, bool) {
	if len(rest) == 0 {
		return nil, false
	}
	switch rest[0] {
	case "uuid":
		return NewUUID(), true
	case "seq":
		if ctx.Seq == nil {
			return float64(1), true
		}
		return float64(ctx.Seq()), true
	case "hex", "alnum":
		n := 32
		if len(rest) > 1 {
			if v, err := strconv.Atoi(rest[1]); err == nil && v > 0 && v <= 4096 {
				n = v
			}
		}
		if rest[0] == "hex" {
			return RandomHex(n), true
		}
		return RandomAlnum(n), true
	}
	return nil, false
}

// RandomHex returns n random hex characters.
func RandomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

// RandomAlnum returns n random alphanumeric characters.
func RandomAlnum(n int) string {
	var sb strings.Builder
	max := big.NewInt(int64(len(alnum)))
	for range n {
		i, err := rand.Int(rand.Reader, max)
		if err != nil {
			i = big.NewInt(0)
		}
		sb.WriteByte(alnum[i.Int64()])
	}
	return sb.String()
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// GetPath reads a dotted path from a JSON value.
func GetPath(v any, p string) (any, bool) {
	if p == "" {
		return v, true
	}
	return path(v, strings.Split(p, "."))
}

// SetPath writes a dotted path into a JSON value, creating objects as needed.
func SetPath(v any, p string, value any) any {
	if p == "" {
		return value
	}
	root, ok := v.(map[string]any)
	if !ok {
		root = map[string]any{}
	}
	segs := strings.Split(p, ".")
	cur := root
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = value
	return root
}
