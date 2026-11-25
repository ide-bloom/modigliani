package hass

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func TestDiscoveryPayloads(t *testing.T) {
	p := testutil.Profile(t)
	dev := engine.DeviceView{Profile: "lab", Key: "SN-1"}
	msgs := DiscoveryMessages("homeassistant", "modigliani", dev, p.Profile)
	byPlatform := map[string]map[string]any{}
	for _, m := range msgs {
		parts := strings.Split(m.Topic, "/")
		if len(parts) != 5 || parts[0] != "homeassistant" || parts[2] != "lab_sn_1" || parts[4] != "config" {
			t.Errorf("topic %s", m.Topic)
		}
		var cfg map[string]any
		if err := json.Unmarshal(m.Payload, &cfg); err != nil {
			t.Fatal(err)
		}
		byPlatform[parts[1]] = cfg
	}
	for _, platform := range []string{"switch", "sensor", "climate", "light", "number", "select", "binary_sensor"} {
		if byPlatform[platform] == nil {
			t.Errorf("missing %s", platform)
		}
	}
	sw := byPlatform["switch"]
	if sw["command_topic"] != "modigliani/lab_sn_1/set/power" || sw["value_template"] != "{{ 'ON' if value_json.power else 'OFF' }}" ||
		sw["unique_id"] != "modigliani_lab_sn_1_power" || sw["state_topic"] != "modigliani/lab_sn_1/state" {
		t.Errorf("switch %v", sw)
	}
	sensor := byPlatform["sensor"]
	if sensor["unit_of_measurement"] != "W" || sensor["device_class"] != "power" || sensor["state_class"] != "measurement" {
		t.Errorf("sensor %v", sensor)
	}
	cl := byPlatform["climate"]
	if cl["temperature_command_topic"] != "modigliani/lab_sn_1/set/setpoint" || cl["mode_command_topic"] != "modigliani/lab_sn_1/set_hvac/mode" ||
		cl["min_temp"] != 5.0 || cl["temp_step"] != 0.5 || cl["mode_state_template"] != "{{ value_json.__hvac_mode }}" {
		t.Errorf("climate %v", cl)
	}
	if modes := cl["modes"].([]any); len(modes) != 2 {
		t.Errorf("modes %v", modes)
	}
	if byPlatform["number"]["max"] != 10.0 || len(byPlatform["select"]["options"].([]any)) != 2 {
		t.Errorf("number/select %v %v", byPlatform["number"], byPlatform["select"])
	}
	avail := sw["availability"].([]any)
	if len(avail) != 2 || sw["availability_mode"] != "all" {
		t.Errorf("availability %v", avail)
	}
}

func TestStateAndCommands(t *testing.T) {
	p := testutil.Profile(t)
	var doc map[string]any
	_ = json.Unmarshal(StatePayload(p.Profile, map[string]any{"mode": "cool", "setpoint": 21.0}), &doc)
	if doc["__hvac_mode"] != "cool" || doc["setpoint"] != 21.0 {
		t.Errorf("state %v", doc)
	}
	topics := NewTopics("modigliani", "lab_sn_1")
	if v, val, ok := ParseCommand(p.Profile, topics, "modigliani/lab_sn_1/set/power", "ON"); !ok || v != "power" || val != "ON" {
		t.Errorf("set: %v %v %v", v, val, ok)
	}
	if v, val, ok := ParseCommand(p.Profile, topics, "modigliani/lab_sn_1/set_hvac/mode", "cool"); !ok || v != "mode" || val != "cool" {
		t.Errorf("hvac: %v %v %v", v, val, ok)
	}
	if _, _, ok := ParseCommand(p.Profile, topics, "modigliani/lab_sn_1/set_hvac/mode", "dry"); ok {
		t.Error("unmapped HA modes are rejected")
	}
	if Slug("My.Profile", "AA:BB/CC") != "my_profile_aa_bb_cc" {
		t.Errorf("slug %s", Slug("My.Profile", "AA:BB/CC"))
	}
}
