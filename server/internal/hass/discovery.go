// Package hass publishes Home Assistant MQTT discovery for revived devices to the user's
// broker and turns Home Assistant commands back into device commands.
package hass

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/profile"
)

// Message is one retained MQTT message to publish.
type Message struct {
	Topic   string
	Payload []byte
}

var unsafeChars = regexp.MustCompile(`[^a-z0-9_]+`)

// Slug turns a device id into a topic- and entity-id-safe string.
func Slug(profileID, key string) string {
	s := unsafeChars.ReplaceAllString(strings.ToLower(profileID+"_"+key), "_")
	return strings.Trim(s, "_")
}

// Topics is the topic layout for one device under the base topic.
type Topics struct {
	Base         string
	Slug         string
	State        string
	Availability string
	Status       string
}

// NewTopics builds the topic layout.
func NewTopics(base, slug string) Topics {
	return Topics{Base: base, Slug: slug, State: base + "/" + slug + "/state",
		Availability: base + "/" + slug + "/availability", Status: base + "/status"}
}

// SetTopic is where Home Assistant sends a new value for a variable.
func (t Topics) SetTopic(variable string) string { return t.Base + "/" + t.Slug + "/set/" + variable }

// HVACTopic receives Home Assistant HVAC modes, which are mapped back to device values.
func (t Topics) HVACTopic(variable string) string {
	return t.Base + "/" + t.Slug + "/set_hvac/" + variable
}

// StatePayload is the JSON state document: reported values plus derived climate fields.
func StatePayload(p *profile.Profile, state map[string]any) []byte {
	doc := map[string]any{}
	for k, v := range state {
		doc[k] = v
	}
	for _, e := range p.HomeAssistant.Entities {
		if e.Platform != "climate" {
			continue
		}
		if e.HVACMode != nil {
			mode := "off"
			if v, ok := state[*e.HVACMode]; ok {
				if m, ok := e.HVACModeMap[toText(v)]; ok {
					mode = m
				}
			}
			doc["__hvac_mode"] = mode
		}
		if e.HVACAction != nil {
			action := "idle"
			if b, ok := state[*e.HVACAction].(bool); ok && b {
				action = "heating"
				if e.HVACMode != nil && doc["__hvac_mode"] == "cool" {
					action = "cooling"
				}
			}
			doc["__hvac_action"] = action
		}
	}
	data, _ := json.Marshal(doc)
	return data
}

func toText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func device(dev engine.DeviceView, p *profile.Profile, slug string) map[string]any {
	d := map[string]any{"identifiers": []string{"modigliani_" + slug}, "name": p.Name + " " + dev.Key,
		"via_device": "modigliani_server"}
	if p.Device.Vendor != "" && p.Device.Vendor != "unknown" {
		d["manufacturer"] = p.Device.Vendor
	}
	if p.Device.Model != "" && p.Device.Model != "unknown" {
		d["model"] = p.Device.Model
	}
	return d
}

func boolTemplate(variable string) string {
	return "{{ 'ON' if value_json." + variable + " else 'OFF' }}"
}

// DiscoveryMessages builds the retained discovery configs for a device's entities.
func DiscoveryMessages(prefix, base string, dev engine.DeviceView, p *profile.Profile) []Message {
	slug := Slug(dev.Profile, dev.Key)
	t := NewTopics(base, slug)
	var out []Message
	for _, e := range p.HomeAssistant.Entities {
		cfg := map[string]any{
			"name":              e.Name,
			"unique_id":         "modigliani_" + slug + "_" + e.Key,
			"object_id":         slug + "_" + e.Key,
			"device":            device(dev, p, slug),
			"availability":      []map[string]string{{"topic": t.Status}, {"topic": t.Availability}},
			"availability_mode": "all",
			"state_topic":       t.State,
			"origin":            map[string]string{"name": "Modigliani", "url": "https://github.com/ide-bloom/modigliani"},
		}
		if e.Platform == "climate" {
			cfg["name"] = nil // the device name is the entity name
		}
		v := ""
		if e.Variable != nil {
			v = *e.Variable
		}
		switch e.Platform {
		case "switch", "light":
			if e.Platform == "light" {
				cfg["state_value_template"] = boolTemplate(v)
			} else {
				cfg["value_template"] = boolTemplate(v)
			}
			cfg["command_topic"] = t.SetTopic(v)
			cfg["payload_on"], cfg["payload_off"] = "ON", "OFF"
		case "binary_sensor":
			cfg["value_template"] = boolTemplate(v)
			setOpt(cfg, "device_class", e.DeviceClass)
		case "sensor":
			cfg["value_template"] = "{{ value_json." + v + " }}"
			setOpt(cfg, "unit_of_measurement", e.Unit)
			setOpt(cfg, "device_class", e.DeviceClass)
			setOpt(cfg, "state_class", e.StateClass)
			if len(e.Options) > 0 {
				cfg["options"] = e.Options
			}
		case "number":
			cfg["value_template"] = "{{ value_json." + v + " }}"
			cfg["command_topic"] = t.SetTopic(v)
			setOpt(cfg, "unit_of_measurement", e.Unit)
			setNum(cfg, "min", e.Min)
			setNum(cfg, "max", e.Max)
			setNum(cfg, "step", e.Step)
		case "select":
			cfg["value_template"] = "{{ value_json." + v + " }}"
			cfg["command_topic"] = t.SetTopic(v)
			cfg["options"] = e.Options
		case "climate":
			delete(cfg, "state_topic")
			if e.CurrentTemperature != nil {
				cfg["current_temperature_topic"] = t.State
				cfg["current_temperature_template"] = "{{ value_json." + *e.CurrentTemperature + " }}"
			}
			if e.TargetTemperature != nil {
				cfg["temperature_state_topic"] = t.State
				cfg["temperature_state_template"] = "{{ value_json." + *e.TargetTemperature + " }}"
				cfg["temperature_command_topic"] = t.SetTopic(*e.TargetTemperature)
			}
			if e.HVACMode != nil && len(e.HVACModeMap) > 0 {
				cfg["mode_state_topic"] = t.State
				cfg["mode_state_template"] = "{{ value_json.__hvac_mode }}"
				cfg["mode_command_topic"] = t.HVACTopic(*e.HVACMode)
				modes := []string{}
				for _, m := range e.HVACModeMap {
					if !slices.Contains(modes, m) {
						modes = append(modes, m)
					}
				}
				slices.Sort(modes)
				cfg["modes"] = modes
			} else {
				cfg["modes"] = []string{"heat"}
			}
			if e.HVACAction != nil {
				cfg["action_topic"] = t.State
				cfg["action_template"] = "{{ value_json.__hvac_action }}"
			}
			cfg["temperature_unit"] = "C"
			if e.Unit != nil && strings.Contains(*e.Unit, "F") {
				cfg["temperature_unit"] = "F"
			}
			setNum(cfg, "min_temp", e.Min)
			setNum(cfg, "max_temp", e.Max)
			setNum(cfg, "temp_step", e.Step)
		default:
			continue
		}
		data, _ := json.Marshal(cfg)
		out = append(out, Message{Topic: prefix + "/" + e.Platform + "/" + slug + "/" + e.Key + "/config", Payload: data})
	}
	return out
}

func setOpt(cfg map[string]any, key string, v *string) {
	if v != nil && *v != "" {
		cfg[key] = *v
	}
}

func setNum(cfg map[string]any, key string, v *float64) {
	if v != nil {
		cfg[key] = *v
	}
}

// ParseCommand maps a Home Assistant command topic and payload to (variable, value).
func ParseCommand(p *profile.Profile, t Topics, topic, payload string) (string, any, bool) {
	if v, ok := strings.CutPrefix(topic, t.Base+"/"+t.Slug+"/set_hvac/"); ok {
		for _, e := range p.HomeAssistant.Entities {
			if e.Platform == "climate" && e.HVACMode != nil && *e.HVACMode == v {
				for deviceValue, haMode := range e.HVACModeMap {
					if haMode == payload {
						return v, deviceValue, true
					}
				}
			}
		}
		return "", nil, false
	}
	if v, ok := strings.CutPrefix(topic, t.Base+"/"+t.Slug+"/set/"); ok {
		return v, payload, true
	}
	return "", nil, false
}
