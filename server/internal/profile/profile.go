// Package profile defines the Modigliani device profile (schema version 1) and loads it.
//
// The types mirror studio/src/modigliani/profile/model.py. JSON field names are the
// contract; YAML files are decoded generically and re-encoded as JSON so that a single set
// of struct tags serves both formats.
package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SchemaVersion is the only profile schema version this server understands.
const SchemaVersion = 1

// StatusNotRevivable marks profiles of devices that strictly verify certificates.
const StatusNotRevivable = "not_revivable_without_firmware_access"

type Evidence struct {
	Capture string `json:"capture"`
	Flow    int    `json:"flow"`
	Message int    `json:"message"`
}

type Fingerprint struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

type Revivability struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

type DeviceInfo struct {
	Vendor       string        `json:"vendor"`
	Model        string        `json:"model"`
	Description  string        `json:"description"`
	Fingerprints []Fingerprint `json:"fingerprints"`
}

type DNSConfig struct {
	Names []string `json:"names"`
	TTL   int      `json:"ttl"`
}

type TLSConfig struct {
	Mode      string   `json:"mode"`
	Hostnames []string `json:"hostnames"`
}

type Placeholder struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Value       any    `json:"value"`
}

type TokenSpec struct {
	Format    string `json:"format"`
	Length    int    `json:"length"`
	Prefix    string `json:"prefix"`
	LifetimeS *int   `json:"lifetime_s"`
	Location  string `json:"location"`
	Name      string `json:"name"`
	IssuedBy  string `json:"issued_by"`
}

type MQTTAuth struct {
	ClientIDPattern string `json:"client_id_pattern"`
	UsernamePattern string `json:"username_pattern"`
	Password        string `json:"password"`
}

type AuthConfig struct {
	Token *TokenSpec `json:"token"`
	MQTT  *MQTTAuth  `json:"mqtt"`
}

type Extract struct {
	Source   string         `json:"source"`
	Variable string         `json:"variable"`
	Scale    *float64       `json:"scale"`
	ValueMap map[string]any `json:"value_map"`
}

type HTTPResponse struct {
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	BodyType string            `json:"body_type"`
	Body     any               `json:"body"`
}

type CommandDelivery struct {
	Mode string `json:"mode"`
	Path string `json:"path"`
}

type HTTPHandler struct {
	ID               string           `json:"id"`
	Host             string           `json:"host"`
	Method           string           `json:"method"`
	Path             string           `json:"path"`
	Identity         string           `json:"identity"`
	Auth             string           `json:"auth"`
	Extract          []Extract        `json:"extract"`
	Response         HTTPResponse     `json:"response"`
	DeliversCommands *CommandDelivery `json:"delivers_commands"`
	Housekeeping     string           `json:"housekeeping"`
	PollingIntervalS *float64         `json:"polling_interval_s"`
}

type WSMessageRule struct {
	ID      string         `json:"id"`
	Match   map[string]any `json:"match"`
	Extract []Extract      `json:"extract"`
	Reply   any            `json:"reply"`
}

type WebSocketHandler struct {
	ID       string          `json:"id"`
	Host     string          `json:"host"`
	Path     string          `json:"path"`
	Identity string          `json:"identity"`
	Messages []WSMessageRule `json:"messages"`
}

type MQTTTopic struct {
	ID           string    `json:"id"`
	Topic        string    `json:"topic"`
	Direction    string    `json:"direction"`
	QoS          int       `json:"qos"`
	Retain       bool      `json:"retain"`
	PayloadType  string    `json:"payload_type"`
	Extract      []Extract `json:"extract"`
	ReplyTo      string    `json:"reply_to"`
	Payload      any       `json:"payload"`
	Housekeeping string    `json:"housekeeping"`
}

type MQTTConfig struct {
	Hosts          []string    `json:"hosts"`
	Ports          []int       `json:"ports"`
	TLS            bool        `json:"tls"`
	ProtocolLevels []int       `json:"protocol_levels"`
	KeepaliveS     *int        `json:"keepalive_s"`
	IdentityVar    string      `json:"identity_var"`
	Topics         []MQTTTopic `json:"topics"`
}

type FrameField struct {
	Name   string  `json:"name"`
	Offset int     `json:"offset"`
	Type   string  `json:"type"`
	Scale  float64 `json:"scale"`
	Const  *int64  `json:"const"`
}

type LengthField struct {
	Offset int    `json:"offset"`
	Type   string `json:"type"`
	Adjust int    `json:"adjust"`
}

type Checksum struct {
	Algorithm string `json:"algorithm"`
	Offset    int    `json:"offset"`
	Start     int    `json:"start"`
	End       int    `json:"end"`
	Endian    string `json:"endian"`
}

type Frame struct {
	ID          string       `json:"id"`
	Length      *int         `json:"length"`
	Fields      []FrameField `json:"fields"`
	LengthField *LengthField `json:"length_field"`
	Checksum    *Checksum    `json:"checksum"`
}

type FramePayload struct {
	Frame  string         `json:"frame"`
	Values map[string]any `json:"values"`
}

type CoAPResponse struct {
	Code          string        `json:"code"`
	ContentFormat *int          `json:"content_format"`
	PayloadType   string        `json:"payload_type"`
	Payload       any           `json:"payload"`
	Frame         *FramePayload `json:"frame"`
}

type CoAPHandler struct {
	ID           string       `json:"id"`
	Method       string       `json:"method"`
	Path         string       `json:"path"`
	Identity     string       `json:"identity"`
	RequestFrame string       `json:"request_frame"`
	Extract      []Extract    `json:"extract"`
	Response     CoAPResponse `json:"response"`
	Housekeeping string       `json:"housekeeping"`
}

type Framing struct {
	Kind        string       `json:"kind"`
	Delimiter   string       `json:"delimiter"`
	LengthField *LengthField `json:"length_field"`
	RecordSize  *int         `json:"record_size"`
}

type RawRule struct {
	ID      string           `json:"id"`
	Match   map[string]int64 `json:"match"`
	Frame   string           `json:"frame"`
	Extract []Extract        `json:"extract"`
	Reply   *FramePayload    `json:"reply"`
}

type RawHandler struct {
	ID        string    `json:"id"`
	Transport string    `json:"transport"`
	Port      int       `json:"port"`
	Host      string    `json:"host"`
	Framing   Framing   `json:"framing"`
	Identity  string    `json:"identity"`
	Rules     []RawRule `json:"rules"`
}

type Handlers struct {
	HTTP      []HTTPHandler      `json:"http"`
	WebSocket []WebSocketHandler `json:"websocket"`
	MQTT      *MQTTConfig        `json:"mqtt"`
	CoAP      []CoAPHandler      `json:"coap"`
	Raw       []RawHandler       `json:"raw"`
}

type StateVariable struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Unit     *string  `json:"unit"`
	Min      *float64 `json:"min"`
	Max      *float64 `json:"max"`
	Step     *float64 `json:"step"`
	Options  []any    `json:"options"`
	Writable bool     `json:"writable"`
}

type Command struct {
	Name      string         `json:"name"`
	Variable  string         `json:"variable"`
	Transport string         `json:"transport"`
	Handler   string         `json:"handler"`
	Template  any            `json:"template"`
	ValueMap  map[string]any `json:"value_map"`
	Scale     *float64       `json:"scale"`
}

type HAEntity struct {
	Platform           string            `json:"platform"`
	Key                string            `json:"key"`
	Name               string            `json:"name"`
	Variable           *string           `json:"variable"`
	Unit               *string           `json:"unit"`
	DeviceClass        *string           `json:"device_class"`
	StateClass         *string           `json:"state_class"`
	Min                *float64          `json:"min"`
	Max                *float64          `json:"max"`
	Step               *float64          `json:"step"`
	Options            []string          `json:"options"`
	CurrentTemperature *string           `json:"current_temperature"`
	TargetTemperature  *string           `json:"target_temperature"`
	HVACMode           *string           `json:"hvac_mode"`
	HVACModeMap        map[string]string `json:"hvac_mode_map"`
	HVACAction         *string           `json:"hvac_action"`
}

type HomeAssistant struct {
	Entities []HAEntity `json:"entities"`
}

type Housekeeping struct {
	TimeSource  string  `json:"time_source"`
	TimeOffsetS float64 `json:"time_offset_s"`
	Firmware    string  `json:"firmware"`
}

type Defaults struct {
	HTTP     HTTPResponse `json:"http"`
	CoAPCode string       `json:"coap_code"`
}

type Provenance struct {
	GeneratedBy string  `json:"generated_by"`
	Created     string  `json:"created"`
	Author      *string `json:"author"`
	License     *string `json:"license"`
	Scrubbed    bool    `json:"scrubbed"`
}

// Profile is one device model's replacement-cloud description.
type Profile struct {
	SchemaVersion int                    `json:"schema_version"`
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Device        DeviceInfo             `json:"device"`
	Revivability  Revivability           `json:"revivability"`
	DNS           DNSConfig              `json:"dns"`
	TLS           TLSConfig              `json:"tls"`
	Placeholders  map[string]Placeholder `json:"placeholders"`
	Auth          AuthConfig             `json:"auth"`
	State         []StateVariable        `json:"state"`
	Commands      []Command              `json:"commands"`
	Frames        []Frame                `json:"frames"`
	Handlers      Handlers               `json:"handlers"`
	Housekeeping  Housekeeping           `json:"housekeeping"`
	Defaults      Defaults               `json:"defaults"`
	HomeAssistant HomeAssistant          `json:"home_assistant"`
	Provenance    Provenance             `json:"provenance"`
}

// Variable returns the named state variable.
func (p *Profile) Variable(name string) (StateVariable, bool) {
	for _, v := range p.State {
		if v.Name == name {
			return v, true
		}
	}
	return StateVariable{}, false
}

// Frame returns the named frame layout.
func (p *Profile) Frame(id string) (Frame, bool) {
	for _, f := range p.Frames {
		if f.ID == id {
			return f, true
		}
	}
	return Frame{}, false
}

// CommandFor returns the command that writes a variable.
func (p *Profile) CommandFor(variable string) (Command, bool) {
	for _, c := range p.Commands {
		if c.Variable == variable {
			return c, true
		}
	}
	return Command{}, false
}

// CommandByName returns the named command.
func (p *Profile) CommandByName(name string) (Command, bool) {
	for _, c := range p.Commands {
		if c.Name == name {
			return c, true
		}
	}
	return Command{}, false
}

// PlaceholderValues returns the filled placeholder values.
func (p *Profile) PlaceholderValues() map[string]any {
	out := make(map[string]any, len(p.Placeholders))
	for k, v := range p.Placeholders {
		if v.Value != nil {
			out[k] = v.Value
		}
	}
	return out
}

// Parse decodes a profile from YAML or JSON bytes.
func Parse(data []byte, name string) (*Profile, error) {
	var generic any
	if strings.HasSuffix(name, ".json") {
		if err := json.Unmarshal(data, &generic); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	} else if err := yaml.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	normalized, err := json.Marshal(normalize(generic))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var p Profile
	dec := json.NewDecoder(bytes.NewReader(normalized))
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%s: unsupported schema_version %d (want %d)", name, p.SchemaVersion, SchemaVersion)
	}
	if p.ID == "" {
		return nil, fmt.Errorf("%s: missing id", name)
	}
	return &p, nil
}

// normalize converts YAML's map[string]any / map[any]any trees into JSON-compatible values.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = normalize(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[fmt.Sprint(k)] = normalize(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = normalize(val)
		}
		return out
	default:
		return v
	}
}

// LoadFile reads and parses one profile file.
func LoadFile(path string) (*Profile, []byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // profile paths are chosen by the operator
	if err != nil {
		return nil, nil, err
	}
	p, err := Parse(data, filepath.Base(path))
	return p, data, err
}

// IsProfileFile reports whether a path looks like a profile (not a signature).
func IsProfileFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}
