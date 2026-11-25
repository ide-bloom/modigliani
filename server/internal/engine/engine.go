// Package engine is the protocol-independent core of Modigliani Server: it tracks devices,
// turns extracted values into state, queues and encodes commands, and builds the template
// contexts that protocol handlers render responses with.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/store"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// Event is published on state or device changes (consumed by the API and HA discovery).
type Event struct {
	Type     string    `json:"type"` // "device" | "state" | "command"
	Profile  string    `json:"profile"`
	Key      string    `json:"key"`
	Variable string    `json:"variable,omitempty"`
	Value    any       `json:"value,omitempty"`
	Time     time.Time `json:"time"`
}

// Publisher publishes an MQTT message to a device through the embedded broker.
type Publisher func(topic string, payload []byte, qos byte, retain bool) error

// Sender pushes a message over an open device connection (WebSocket or raw TCP).
type Sender func(payload []byte) error

// Options tune the engine.
type Options struct {
	TimeOffset    time.Duration
	DeviceTimeout time.Duration
	Now           func() time.Time
}

// Engine is safe for concurrent use.
type Engine struct {
	log      *slog.Logger
	store    *store.Store
	profiles []*Loaded
	byID     map[string]*Loaded
	opts     Options

	mu      sync.Mutex
	subs    map[int]chan Event
	nextSub int
	publish Publisher
	senders map[string]Sender
}

// ErrUnknownDevice is returned for commands to devices the server has not seen.
var ErrUnknownDevice = errors.New("unknown device")

// New builds an engine over loaded profiles.
func New(log *slog.Logger, st *store.Store, profiles []*Loaded, opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DeviceTimeout == 0 {
		opts.DeviceTimeout = 2 * time.Minute
	}
	byID := make(map[string]*Loaded, len(profiles))
	for _, p := range profiles {
		byID[p.ID] = p
	}
	return &Engine{log: log, store: st, profiles: profiles, byID: byID, opts: opts,
		subs: map[int]chan Event{}, senders: map[string]Sender{}}
}

// Profiles returns the loaded profiles.
func (e *Engine) Profiles() []*Loaded { return e.profiles }

// Profile returns a profile by id.
func (e *Engine) Profile(id string) (*Loaded, bool) {
	p, ok := e.byID[id]
	return p, ok
}

// Store exposes the state store.
func (e *Engine) Store() *store.Store { return e.store }

// Now is the time the server presents to devices (system time plus configured offsets).
func (e *Engine) Now(p *Loaded) time.Time {
	t := e.opts.Now().Add(e.opts.TimeOffset)
	if p != nil && p.Housekeeping.TimeSource == "offset" {
		t = t.Add(time.Duration(p.Housekeeping.TimeOffsetS * float64(time.Second)))
	}
	return t
}

// SetPublisher wires the embedded MQTT broker.
func (e *Engine) SetPublisher(p Publisher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.publish = p
}

func senderKey(profileID, key string) string { return profileID + "\x00" + key }

// RegisterSender records an open connection to a device; call the returned func on close.
func (e *Engine) RegisterSender(profileID, key string, s Sender) func() {
	e.mu.Lock()
	defer e.mu.Unlock()
	k := senderKey(profileID, key)
	e.senders[k] = s
	return func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		delete(e.senders, k)
	}
}

// Subscribe returns a channel of events; call cancel when done.
func (e *Engine) Subscribe() (<-chan Event, func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id := e.nextSub
	e.nextSub++
	ch := make(chan Event, 256)
	e.subs[id] = ch
	return ch, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if c, ok := e.subs[id]; ok {
			delete(e.subs, id)
			close(c)
		}
	}
}

func (e *Engine) emit(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ch := range e.subs {
		select {
		case ch <- ev:
		default: // a slow subscriber must not block devices
		}
	}
}

// Touch records that a device was seen and remembers learned variables (path/topic params).
func (e *Engine) Touch(ctx context.Context, p *Loaded, key, remote string, vars map[string]string) {
	isNew, err := e.store.Touch(ctx, p.ID, key, remote, vars, e.opts.Now())
	if err != nil {
		e.log.Error("store device", "err", err)
		return
	}
	if isNew {
		e.log.Info("new device", "profile", p.ID, "device", key, "remote", remote)
		e.emit(Event{Type: "device", Profile: p.ID, Key: key, Time: e.opts.Now()})
	}
}

// jsonText renders a value the way Python's json.dumps does for map keys.
func jsonText(v any) []string {
	switch t := v.(type) {
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			i := strconv.FormatInt(int64(t), 10)
			return []string{i, i + ".0"}
		}
		return []string{strconv.FormatFloat(t, 'f', -1, 64)}
	default:
		b, _ := json.Marshal(v)
		return []string{string(b)}
	}
}

func mapValue(m map[string]any, v any) (any, bool) {
	for _, k := range jsonText(v) {
		if out, ok := m[k]; ok {
			return out, true
		}
	}
	return nil, false
}

// Coerce converts a value to a variable's declared type.
func Coerce(sv profile.StateVariable, v any) (any, error) {
	switch sv.Type {
	case "bool":
		switch t := v.(type) {
		case bool:
			return t, nil
		case float64:
			return t != 0, nil
		case string:
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "on", "true", "1", "yes", "open":
				return true, nil
			case "off", "false", "0", "no", "closed":
				return false, nil
			}
		}
		return nil, fmt.Errorf("%s: not a boolean: %v", sv.Name, v)
	case "int", "float":
		var f float64
		switch t := v.(type) {
		case float64:
			f = t
		case bool:
			if t {
				f = 1
			}
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
			if err != nil {
				return nil, fmt.Errorf("%s: not a number: %q", sv.Name, t)
			}
			f = parsed
		default:
			return nil, fmt.Errorf("%s: not a number: %v", sv.Name, v)
		}
		if sv.Type == "int" {
			f = math.Round(f)
		}
		return f, nil
	default:
		if s, ok := v.(string); ok {
			return s, nil
		}
		return tmpl.Text(v), nil
	}
}

// ApplyExtracts copies values from an incoming message (in req) into reported state.
func (e *Engine) ApplyExtracts(ctx context.Context, p *Loaded, key string, extracts []profile.Extract, req map[string]any) {
	tctx := &tmpl.Context{Req: req}
	for _, x := range extracts {
		raw, ok := tmpl.Lookup(x.Source, tctx)
		if !ok || raw == nil {
			continue
		}
		v := raw
		if x.ValueMap != nil {
			if mapped, ok := mapValue(x.ValueMap, raw); ok {
				v = mapped
			}
		}
		if x.Scale != nil {
			if f, ok := v.(float64); ok {
				v = math.Round(f**x.Scale*1e6) / 1e6
			}
		}
		sv, ok := p.Variable(x.Variable)
		if !ok {
			continue
		}
		cv, err := Coerce(sv, v)
		if err != nil {
			e.log.Debug("extract skipped", "profile", p.ID, "variable", x.Variable, "err", err)
			continue
		}
		changed, err := e.store.SetReported(ctx, p.ID, key, x.Variable, cv, e.opts.Now())
		if err != nil {
			e.log.Error("store state", "err", err)
			continue
		}
		if changed {
			e.emit(Event{Type: "state", Profile: p.ID, Key: key, Variable: x.Variable, Value: cv, Time: e.opts.Now()})
		}
	}
}

// EncodeForDevice converts a state value into what the device expects on the wire, using
// the encoding of the command that writes the variable (value map and scale).
func EncodeForDevice(p *profile.Profile, variable string, v any) any {
	cmd, ok := p.CommandFor(variable)
	if !ok {
		return v
	}
	if cmd.ValueMap != nil {
		if mapped, ok := mapValue(cmd.ValueMap, v); ok {
			v = mapped
		}
	}
	if cmd.Scale != nil && *cmd.Scale != 0 {
		if f, ok := v.(float64); ok {
			v = math.Round(f / *cmd.Scale)
		}
	}
	return v
}

// Context builds the template context for rendering a response to a device.
func (e *Engine) Context(ctx context.Context, p *Loaded, key string, req map[string]any) *tmpl.Context {
	state := map[string]any{}
	desired := map[string]any{}
	vars := map[string]any{}
	if key != "" {
		values, err := e.store.State(ctx, p.ID, key)
		if err != nil {
			e.log.Error("read state", "err", err)
		}
		for name, v := range values {
			state[name] = EncodeForDevice(p.Profile, name, v.Reported)
			d := v.Desired
			if d == nil {
				d = v.Reported
			}
			desired[name] = EncodeForDevice(p.Profile, name, d)
		}
		if dev, ok, _ := e.store.Device(ctx, p.ID, key); ok {
			for k, v := range dev.Vars {
				vars[k] = v
			}
		}
	}
	return &tmpl.Context{
		Req:     req,
		Device:  map[string]any{"key": key, "vars": vars},
		State:   state,
		Desired: desired,
		Ph:      p.PlaceholderValues(),
		Now:     e.Now(p),
		Seq: func() int64 {
			v, err := e.store.NextSeq(ctx, p.ID, key, "seq")
			if err != nil {
				e.log.Error("counter", "err", err)
			}
			return v
		},
	}
}

// IssueToken creates a token in the profile's format and binds it to the device.
func (e *Engine) IssueToken(ctx context.Context, p *Loaded, key string) (map[string]any, error) {
	spec := p.Auth.Token
	if spec == nil {
		return nil, errors.New("profile has no token specification")
	}
	n := spec.Length
	if n <= 0 {
		n = 32
	}
	var value string
	switch spec.Format {
	case "uuid":
		value = tmpl.NewUUID()
	case "jwt":
		value = jwtShaped(e.Now(p), lifetime(spec))
	case "numeric":
		value = numeric(n)
	case "alnum", "base64url":
		value = tmpl.RandomAlnum(n)
	default:
		value = tmpl.RandomHex(n)
	}
	value = spec.Prefix + value
	life := lifetime(spec)
	expires := e.opts.Now().Add(time.Duration(life) * time.Second)
	if err := e.store.IssueToken(ctx, value, p.ID, key, expires); err != nil {
		return nil, err
	}
	return map[string]any{"value": value, "expires_in": float64(life), "expires_at": float64(e.Now(p).Unix() + int64(life))}, nil
}

func lifetime(spec *profile.TokenSpec) int {
	if spec.LifetimeS != nil && *spec.LifetimeS > 0 {
		return *spec.LifetimeS
	}
	return 86400
}

// CheckToken returns the device a presented token belongs to.
func (e *Engine) CheckToken(ctx context.Context, p *Loaded, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	key, valid, err := e.store.TokenDevice(ctx, token, p.ID, e.opts.Now())
	if err != nil {
		e.log.Error("token lookup", "err", err)
		return "", false
	}
	return key, valid
}

// TakeCommands returns queued commands a polling handler must deliver now.
func (e *Engine) TakeCommands(ctx context.Context, p *Loaded, key, handlerID string) []store.QueuedCommand {
	var names []string
	for _, c := range p.Commands {
		if c.Transport == "http_poll" && c.Handler == handlerID {
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	cmds, err := e.store.TakeQueued(ctx, p.ID, key, names, e.opts.Now())
	if err != nil {
		e.log.Error("dequeue commands", "err", err)
		return nil
	}
	return cmds
}

// RenderCommand renders a command's template for a value (in state units).
func (e *Engine) RenderCommand(cmd profile.Command, p *Loaded, value any, id int64, base *tmpl.Context) any {
	c := *base
	c.Cmd = map[string]any{
		"value": EncodeForDevice(p.Profile, cmd.Variable, value),
		"name":  cmd.Name,
		"id":    tmpl.NewUUID(),
		"seq":   float64(id),
	}
	return tmpl.Render(cmd.Template, &c)
}

// Unhandled records a request that no handler answered.
func (e *Engine) Unhandled(ctx context.Context, protocol, remote, summary, detail string) {
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	e.log.Info("unhandled request", "protocol", protocol, "remote", remote, "summary", summary)
	if err := e.store.AddUnhandled(ctx, store.Unhandled{TS: e.opts.Now(), Protocol: protocol, Remote: remote, Summary: summary, Detail: detail}); err != nil {
		e.log.Error("store unhandled", "err", err)
	}
}

// CommandResult reports how a command was handled.
type CommandResult struct {
	ID       int64  `json:"id"`
	Command  string `json:"command"`
	Variable string `json:"variable"`
	Value    any    `json:"value"`
	Status   string `json:"status"` // queued | sent | pending_next_contact
}

// SendCommand validates and dispatches a command from the API or Home Assistant. Either
// a variable or a command name identifies it.
func (e *Engine) SendCommand(ctx context.Context, profileID, key, variable, name string, value any) (CommandResult, error) {
	p, ok := e.Profile(profileID)
	if !ok {
		return CommandResult{}, fmt.Errorf("%w: profile %s", ErrUnknownDevice, profileID)
	}
	dev, ok, err := e.store.Device(ctx, p.ID, key)
	if err != nil {
		return CommandResult{}, err
	}
	if !ok {
		return CommandResult{}, fmt.Errorf("%w: %s/%s", ErrUnknownDevice, profileID, key)
	}
	var cmd profile.Command
	if name != "" {
		cmd, ok = p.CommandByName(name)
	} else {
		cmd, ok = p.CommandFor(variable)
	}
	if !ok {
		return CommandResult{}, fmt.Errorf("profile %s has no command for %q", p.ID, variable+name)
	}
	sv, ok := p.Variable(cmd.Variable)
	if !ok || !sv.Writable {
		return CommandResult{}, fmt.Errorf("variable %s is not writable", cmd.Variable)
	}
	v, err := Coerce(sv, value)
	if err != nil {
		return CommandResult{}, err
	}
	if err := validateRange(sv, v); err != nil {
		return CommandResult{}, err
	}
	now := e.opts.Now()
	if err := e.store.SetDesired(ctx, p.ID, key, cmd.Variable, v, now); err != nil {
		return CommandResult{}, err
	}
	res := CommandResult{Command: cmd.Name, Variable: cmd.Variable, Value: v}
	switch cmd.Transport {
	case "http_poll":
		res.Status = "queued"
		res.ID, err = e.store.Enqueue(ctx, p.ID, key, cmd.Name, cmd.Variable, v, "queued", now)
	case "mqtt":
		res.Status = "sent"
		res.ID, err = e.store.Enqueue(ctx, p.ID, key, cmd.Name, cmd.Variable, v, "sent", now)
		if err == nil {
			err = e.publishCommand(ctx, p, dev, cmd, v, res.ID)
		}
	case "websocket", "raw":
		res.Status = "sent"
		res.ID, err = e.store.Enqueue(ctx, p.ID, key, cmd.Name, cmd.Variable, v, "sent", now)
		if err == nil && cmd.Template != nil {
			err = e.pushCommand(ctx, p, key, cmd, v, res.ID)
		} else if err == nil {
			res.Status = "pending_next_contact"
		}
	default: // coap_response: the next answer to the device carries the desired value
		res.Status = "pending_next_contact"
		res.ID, err = e.store.Enqueue(ctx, p.ID, key, cmd.Name, cmd.Variable, v, "pending", now)
	}
	if err != nil {
		return CommandResult{}, err
	}
	e.log.Info("command", "profile", p.ID, "device", key, "command", cmd.Name, "value", v, "status", res.Status)
	e.emit(Event{Type: "command", Profile: p.ID, Key: key, Variable: cmd.Variable, Value: v, Time: now})
	return res, nil
}

func validateRange(sv profile.StateVariable, v any) error {
	switch sv.Type {
	case "int", "float":
		f, _ := v.(float64)
		if sv.Min != nil && f < *sv.Min || sv.Max != nil && f > *sv.Max {
			return fmt.Errorf("%s: %v is outside [%v, %v]", sv.Name, f, deref(sv.Min), deref(sv.Max))
		}
	case "enum":
		if len(sv.Options) > 0 && !slices.ContainsFunc(sv.Options, func(o any) bool { return tmpl.Text(o) == tmpl.Text(v) }) {
			return fmt.Errorf("%s: %v is not one of %v", sv.Name, v, sv.Options)
		}
	}
	return nil
}

func deref(f *float64) any {
	if f == nil {
		return "-"
	}
	return *f
}

func (e *Engine) publishCommand(ctx context.Context, p *Loaded, dev store.Device, cmd profile.Command, v any, id int64) error {
	e.mu.Lock()
	pub := e.publish
	e.mu.Unlock()
	if pub == nil || p.Handlers.MQTT == nil {
		return errors.New("MQTT is not running")
	}
	var topic *profile.MQTTTopic
	for i := range p.Handlers.MQTT.Topics {
		if p.Handlers.MQTT.Topics[i].ID == cmd.Handler {
			topic = &p.Handlers.MQTT.Topics[i]
		}
	}
	if topic == nil {
		return fmt.Errorf("unknown topic %s", cmd.Handler)
	}
	name, ok := profile.FillTemplate(topic.Topic, "/", dev.Vars)
	if !ok {
		return fmt.Errorf("cannot address device %s: topic %s needs variables the device has not sent yet", dev.Key, topic.Topic)
	}
	payload, err := encodePayload(topic.PayloadType, e.RenderCommand(cmd, p, v, id, e.Context(ctx, p, dev.Key, nil)))
	if err != nil {
		return err
	}
	var q byte
	switch {
	case topic.QoS >= 2:
		q = 2
	case topic.QoS == 1:
		q = 1
	}
	return pub(name, payload, q, topic.Retain)
}

func (e *Engine) pushCommand(ctx context.Context, p *Loaded, key string, cmd profile.Command, v any, id int64) error {
	e.mu.Lock()
	send := e.senders[senderKey(p.ID, key)]
	e.mu.Unlock()
	if send == nil {
		return fmt.Errorf("device %s is not connected", key)
	}
	payload, err := json.Marshal(e.RenderCommand(cmd, p, v, id, e.Context(ctx, p, key, nil)))
	if err != nil {
		return err
	}
	return send(payload)
}

func encodePayload(kind string, v any) ([]byte, error) {
	if kind == "text" {
		return []byte(tmpl.Text(v)), nil
	}
	return json.Marshal(v)
}

// EncodePayload renders an MQTT payload according to its declared type.
func EncodePayload(kind string, v any) ([]byte, error) { return encodePayload(kind, v) }

// DeviceView is a device as presented by the API.
type DeviceView struct {
	ID        string                  `json:"id"`
	Profile   string                  `json:"profile"`
	Key       string                  `json:"key"`
	Name      string                  `json:"name"`
	Vendor    string                  `json:"vendor"`
	Model     string                  `json:"model"`
	Online    bool                    `json:"online"`
	FirstSeen time.Time               `json:"first_seen"`
	LastSeen  time.Time               `json:"last_seen"`
	Remote    string                  `json:"remote"`
	State     map[string]any          `json:"state"`
	Desired   map[string]any          `json:"desired"`
	Variables []profile.StateVariable `json:"variables"`
	Entities  []profile.HAEntity      `json:"entities"`
	Commands  []string                `json:"commands"`
	Updated   map[string]time.Time    `json:"updated"`
	Signature string                  `json:"signature"`
}

// Devices returns every known device with its state.
func (e *Engine) Devices(ctx context.Context) ([]DeviceView, error) {
	devs, err := e.store.Devices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceView, 0, len(devs))
	for _, d := range devs {
		p, ok := e.Profile(d.Profile)
		if !ok {
			continue
		}
		values, err := e.store.State(ctx, d.Profile, d.Key)
		if err != nil {
			return nil, err
		}
		v := DeviceView{
			ID: d.Profile + "/" + d.Key, Profile: d.Profile, Key: d.Key, Name: p.Name, Vendor: p.Device.Vendor,
			Model: p.Device.Model, FirstSeen: d.FirstSeen, LastSeen: d.LastSeen, Remote: d.Remote,
			Online: e.opts.Now().Sub(d.LastSeen) <= e.opts.DeviceTimeout, State: map[string]any{},
			Desired: map[string]any{}, Variables: p.State, Entities: p.HomeAssistant.Entities,
			Updated: map[string]time.Time{}, Signature: p.Signature.Status,
		}
		for name, val := range values {
			v.State[name] = val.Reported
			v.Updated[name] = val.Updated
			if val.Desired != nil {
				v.Desired[name] = val.Desired
			}
		}
		for _, c := range p.Commands {
			v.Commands = append(v.Commands, c.Name)
		}
		out = append(out, v)
	}
	return out, nil
}
