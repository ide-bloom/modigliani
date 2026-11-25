// Package mqttserver runs the embedded MQTT broker (mochi-mqtt) that devices connect to in
// place of the vendor's broker.
package mqttserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// Server wraps the broker and the profile logic.
type Server struct {
	eng      *engine.Engine
	cfg      *config.Config
	log      *slog.Logger
	broker   *mqtt.Server
	sessions sync.Map // client id -> *session
}

type session struct {
	p    *engine.Loaded
	key  string
	vars map[string]string
	ip   string
}

// New creates the server.
func New(eng *engine.Engine, cfg *config.Config, log *slog.Logger) *Server {
	return &Server{eng: eng, cfg: cfg, log: log.With("component", "mqtt")}
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context, plain, secure []string, tlsConf *tls.Config) error {
	s.broker = mqtt.New(&mqtt.Options{InlineClient: true, Logger: s.log})
	if err := s.broker.AddHook(&hook{s: s}, nil); err != nil {
		return err
	}
	for _, a := range plain {
		if err := s.broker.AddListener(listeners.NewTCP(listeners.Config{ID: "tcp-" + a, Address: a})); err != nil {
			return err
		}
	}
	for _, a := range secure {
		if tlsConf == nil {
			return fmt.Errorf("MQTT TLS listener %s configured but no local CA is loaded", a)
		}
		if err := s.broker.AddListener(listeners.NewTCP(listeners.Config{ID: "tls-" + a, Address: a, TLSConfig: tlsConf})); err != nil {
			return err
		}
	}
	s.eng.SetPublisher(func(topic string, payload []byte, qos byte, retain bool) error {
		return s.broker.Publish(topic, payload, retain, qos)
	})
	if err := s.broker.Serve(); err != nil {
		return err
	}
	s.log.Info("listening", "plain", plain, "tls", secure)
	<-ctx.Done()
	return s.broker.Close()
}

// authenticate finds the profile whose client-ID/username patterns match a connecting client.
func (s *Server) authenticate(clientID, username, ip string) (*session, bool) {
	for _, p := range s.eng.Profiles() {
		cfgm := p.Handlers.MQTT
		if cfgm == nil {
			continue
		}
		vars := map[string]string{}
		if a := p.Auth.MQTT; a != nil {
			v1, ok1 := profile.MatchPattern(a.ClientIDPattern, clientID)
			v2, ok2 := profile.MatchPattern(a.UsernamePattern, username)
			if !ok1 || !ok2 {
				continue
			}
			for k, v := range v1 {
				vars[k] = v
			}
			for k, v := range v2 {
				vars[k] = v
			}
		}
		key := clientID
		if cfgm.IdentityVar != "" {
			if v, ok := vars[cfgm.IdentityVar]; ok {
				key = v
			}
		}
		return &session{p: p, key: key, vars: vars, ip: ip}, true
	}
	return nil, false
}

func clientIP(cl *mqtt.Client) string {
	host, _, err := net.SplitHostPort(cl.Net.Remote)
	if err != nil {
		return cl.Net.Remote
	}
	return host
}

func (s *Server) onPublish(ctx context.Context, sess *session, topic string, payload []byte) {
	p := sess.p
	matched := false
	for i := range p.Handlers.MQTT.Topics {
		t := &p.Handlers.MQTT.Topics[i]
		if t.Direction != "device_to_cloud" {
			continue
		}
		params, ok := profile.MatchTemplate(t.Topic, topic, "/")
		if !ok {
			continue
		}
		matched = true
		for k, v := range params {
			sess.vars[k] = v
		}
		s.eng.Touch(ctx, p, sess.key, sess.ip, sess.vars)
		req := map[string]any{"topic": toAny(params), "payload": decodePayload(t.PayloadType, payload)}
		s.eng.ApplyExtracts(ctx, p, sess.key, t.Extract, req)
		for j := range p.Handlers.MQTT.Topics {
			reply := &p.Handlers.MQTT.Topics[j]
			if reply.ReplyTo != t.ID {
				continue
			}
			name, ok := profile.FillTemplate(reply.Topic, "/", sess.vars)
			if !ok {
				continue
			}
			out, err := engine.EncodePayload(reply.PayloadType, tmpl.Render(reply.Payload, s.eng.Context(ctx, p, sess.key, req)))
			if err != nil {
				continue
			}
			// Publishing from inside a broker hook would re-enter the broker; hand it off.
			go func(name string, out []byte, qos byte, retain bool) {
				if err := s.broker.Publish(name, out, retain, qos); err != nil {
					s.log.Warn("reply publish failed", "topic", name, "err", err)
				}
			}(name, out, qos(reply.QoS), reply.Retain)
		}
	}
	if !matched {
		s.eng.Unhandled(ctx, "mqtt", sess.ip, "PUBLISH "+topic, string(payload))
	}
}

func decodePayload(kind string, b []byte) any {
	switch kind {
	case "json", "": // json is the schema default
		var v any
		if json.Unmarshal(b, &v) == nil {
			return v
		}
		return string(b)
	case "text":
		return string(b)
	default:
		return b
	}
}

func toAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type hook struct {
	mqtt.HookBase
	s *Server
}

func (h *hook) ID() string { return "modigliani" }

func (h *hook) Provides(b byte) bool {
	return slices.Contains([]byte{mqtt.OnConnectAuthenticate, mqtt.OnACLCheck, mqtt.OnPublish, mqtt.OnDisconnect}, b)
}

func (h *hook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	if cl.Net.Inline {
		return true
	}
	ip := clientIP(cl)
	if !h.s.cfg.IsEnrolled(ip) {
		h.s.log.Info("rejecting MQTT client that is not enrolled", "remote", ip)
		return false
	}
	sess, ok := h.s.authenticate(pk.Connect.ClientIdentifier, string(pk.Connect.Username), ip)
	if !ok {
		h.s.eng.Unhandled(context.Background(), "mqtt", ip, "CONNECT "+pk.Connect.ClientIdentifier,
			fmt.Sprintf("username=%q", string(pk.Connect.Username)))
		return false
	}
	h.s.sessions.Store(pk.Connect.ClientIdentifier, sess)
	h.s.eng.Touch(context.Background(), sess.p, sess.key, ip, sess.vars)
	h.s.log.Info("device connected", "profile", sess.p.ID, "device", sess.key, "client_id", pk.Connect.ClientIdentifier)
	return true
}

func (h *hook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool { return true }

func (h *hook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if cl.Net.Inline {
		return pk, nil
	}
	if v, ok := h.s.sessions.Load(cl.ID); ok {
		h.s.onPublish(context.Background(), v.(*session), pk.TopicName, pk.Payload)
	}
	return pk, nil
}

func (h *hook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	h.s.sessions.Delete(cl.ID)
}

// qos clamps a profile QoS to a valid MQTT level.
func qos(v int) byte {
	switch {
	case v >= 2:
		return 2
	case v == 1:
		return 1
	default:
		return 0
	}
}
