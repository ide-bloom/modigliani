package tmpl

import (
	"regexp"
	"testing"
	"time"
)

func TestRenderTypedAndInterpolated(t *testing.T) {
	ctx := &Context{
		Req:     map[string]any{"path": map[string]any{"id": "SN-1"}, "body": map[string]any{"a": map[string]any{"b": 7.0}}},
		State:   map[string]any{"on": true},
		Desired: map[string]any{"led": 1.0},
		Cmd:     map[string]any{"value": 22.5},
		Token:   map[string]any{"value": "tok"},
		Ph:      map[string]any{"serial": "S1"},
		Now:     time.Unix(1_800_000_000, 0),
		Seq:     func() int64 { return 42 },
	}
	out := Render(map[string]any{
		"id":    "{{req.path.id}}",
		"n":     "{{ req.body.a.b }}",
		"on":    "{{state.on}}",
		"led":   "{{desired.led}}",
		"v":     "{{cmd.value}}",
		"text":  "dev-{{req.path.id}}/{{cmd.value}}",
		"now":   "{{now.unix}}",
		"iso":   "{{now.iso}}",
		"seq":   "{{gen.seq}}",
		"ph":    "{{ph.serial}}",
		"miss":  "{{state.nope}}",
		"list":  []any{"{{token.value}}", 3.0},
		"plain": "no template",
	}, ctx).(map[string]any)
	want := map[string]any{"id": "SN-1", "n": 7.0, "on": true, "led": 1.0, "v": 22.5, "text": "dev-SN-1/22.5",
		"now": 1.8e9, "iso": "2027-01-15T08:00:00Z", "seq": 42.0, "ph": "S1", "plain": "no template"}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %#v, want %#v", k, out[k], v)
		}
	}
	if out["miss"] != nil {
		t.Errorf("missing values render as null, got %#v", out["miss"])
	}
	if l := out["list"].([]any); l[0] != "tok" || l[1] != 3.0 {
		t.Errorf("list = %v", l)
	}
}

func TestGenerators(t *testing.T) {
	ctx := &Context{}
	if v, _ := Lookup("gen.hex.12", ctx); !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(v.(string)) {
		t.Errorf("hex: %v", v)
	}
	if v, _ := Lookup("gen.alnum.20", ctx); len(v.(string)) != 20 {
		t.Errorf("alnum: %v", v)
	}
	if v, _ := Lookup("gen.uuid", ctx); !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(v.(string)) {
		t.Errorf("uuid: %v", v)
	}
	if _, ok := Lookup("bogus.x", ctx); ok {
		t.Error("unknown roots must not resolve")
	}
}

func TestSetAndGetPath(t *testing.T) {
	v := SetPath(map[string]any{"a": map[string]any{}}, "a.b", []any{1.0})
	if got, ok := GetPath(v, "a.b.0"); !ok || got != 1.0 {
		t.Errorf("got %v %v", got, ok)
	}
	if SetPath(nil, "", "x") != "x" {
		t.Error("empty path replaces the value")
	}
}
