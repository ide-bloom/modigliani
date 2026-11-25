package engine_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func TestCoerce(t *testing.T) {
	b := profile.StateVariable{Name: "b", Type: "bool"}
	for in, want := range map[any]bool{"ON": true, "off": false, 1.0: true, true: true} {
		if got, err := engine.Coerce(b, in); err != nil || got != want {
			t.Errorf("bool %v -> %v %v", in, got, err)
		}
	}
	if _, err := engine.Coerce(b, "maybe"); err == nil {
		t.Error("garbage booleans fail")
	}
	if got, _ := engine.Coerce(profile.StateVariable{Type: "int"}, "21.6"); got != 22.0 {
		t.Errorf("int %v", got)
	}
	if got, _ := engine.Coerce(profile.StateVariable{Type: "enum"}, 3.0); got != "3" {
		t.Errorf("enum %v", got)
	}
}

func TestCommandsAndEncoding(t *testing.T) {
	eng := testutil.Engine(t)
	ctx := context.Background()
	p := eng.Profiles()[0]
	if _, err := eng.SendCommand(ctx, "lab", "ghost", "power", "", true); !errors.Is(err, engine.ErrUnknownDevice) {
		t.Errorf("unknown device: %v", err)
	}
	eng.Touch(ctx, p, "K", "10.0.0.1", nil)
	if _, err := eng.SendCommand(ctx, "lab", "K", "watts", "", 3); err == nil {
		t.Error("read-only variables cannot be commanded")
	}
	if _, err := eng.SendCommand(ctx, "lab", "K", "mode", "", "dry"); err == nil {
		t.Error("enum options are enforced")
	}
	res, err := eng.SendCommand(ctx, "lab", "K", "led", "", "on")
	if err != nil || res.Status != "pending_next_contact" || res.Value != true {
		t.Fatalf("led %+v %v", res, err)
	}
	if _, err := eng.SendCommand(ctx, "lab", "K", "setpoint", "", 21); err == nil {
		t.Error("MQTT commands need a running broker")
	}
	tctx := eng.Context(ctx, p, "K", nil)
	if tctx.Desired["led"] != 1.0 {
		t.Errorf("desired value uses the device encoding: %#v", tctx.Desired["led"])
	}
	if got := engine.EncodeForDevice(p.Profile, "power", true); got != "ON" {
		t.Errorf("value map %v", got)
	}
}

func TestTokens(t *testing.T) {
	eng := testutil.Engine(t)
	ctx := context.Background()
	p := eng.Profiles()[0]
	tok, err := eng.IssueToken(ctx, p, "K")
	if err != nil || len(tok["value"].(string)) != 32 || tok["expires_in"] != 3600.0 {
		t.Fatalf("token %v %v", tok, err)
	}
	if key, ok := eng.CheckToken(ctx, p, tok["value"].(string)); !ok || key != "K" {
		t.Error("token check")
	}
	if _, ok := eng.CheckToken(ctx, p, "nope"); ok {
		t.Error("unknown token")
	}
}

func TestLoadProfiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(testutil.ProfileYAML), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "hub.json"), []byte(`{"schema_version":1,"id":"hub","name":"Hub","revivability":{"status":"not_revivable_without_firmware_access"},"provenance":{"generated_by":"t","created":"x"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(testutil.ProfileYAML), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad.yaml.sig"), []byte(`{"algorithm":"ed25519","public_key":"AAAA","signature":"AAAA"}`), 0o600)
	loaded, err := engine.LoadProfiles(testutil.Logger(), []string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].ID != "lab" {
		t.Fatalf("expected only the valid, revivable profile: %v", loaded)
	}
	names := loaded[0].Hostnames()
	if len(names) != 3 || names[2] != "sn-1.lab.example" {
		t.Errorf("placeholders fill DNS names: %v", names)
	}
}
