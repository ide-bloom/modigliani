package hass

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/engine"
)

// Publisher keeps Home Assistant in sync with the engine.
type Publisher struct {
	cfg    *config.HomeAssistant
	eng    *engine.Engine
	log    *slog.Logger
	client paho.Client
	mu     sync.Mutex
	known  map[string]engine.DeviceView // slug -> device
	online map[string]bool
}

// NewPublisher creates the discovery publisher.
func NewPublisher(cfg *config.HomeAssistant, eng *engine.Engine, log *slog.Logger) *Publisher {
	return &Publisher{cfg: cfg, eng: eng, log: log.With("component", "homeassistant"),
		known: map[string]engine.DeviceView{}, online: map[string]bool{}}
}

func (h *Publisher) publish(topic string, payload []byte, retain bool) {
	tok := h.client.Publish(topic, 1, retain, payload)
	go func() {
		if tok.WaitTimeout(10*time.Second) && tok.Error() != nil {
			h.log.Warn("publish failed", "topic", topic, "err", tok.Error())
		}
	}()
}

// Run connects to the user's broker and publishes until ctx is cancelled.
func (h *Publisher) Run(ctx context.Context) error {
	status := h.cfg.BaseTopic + "/status"
	opts := paho.NewClientOptions().AddBroker(h.cfg.Broker).SetClientID(h.cfg.ClientID).
		SetUsername(h.cfg.Username).SetPassword(h.cfg.Password).
		SetWill(status, "offline", 1, true).SetAutoReconnect(true).SetConnectRetry(true).
		SetConnectRetryInterval(2 * time.Second).SetOrderMatters(false).
		SetOnConnectHandler(func(c paho.Client) { h.onConnect(ctx, c) })
	h.client = paho.NewClient(opts)
	h.client.Connect() // with ConnectRetry the client keeps trying in the background
	h.log.Info("publishing Home Assistant discovery", "broker", h.cfg.Broker, "prefix", h.cfg.DiscoveryPrefix)
	events, cancel := h.eng.Subscribe()
	defer cancel()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if h.client.IsConnected() {
				h.client.Publish(status, 1, true, "offline").WaitTimeout(2 * time.Second)
			}
			h.client.Disconnect(500)
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			if ev.Type == "device" || ev.Type == "state" {
				h.sync(ctx, ev.Profile, ev.Key)
			}
		case <-ticker.C:
			h.sync(ctx, "", "")
		}
	}
}

func (h *Publisher) onConnect(ctx context.Context, c paho.Client) {
	h.log.Info("connected to Home Assistant broker")
	h.mu.Lock()
	h.known = map[string]engine.DeviceView{}
	h.online = map[string]bool{}
	h.mu.Unlock()
	c.Publish(h.cfg.BaseTopic+"/status", 1, true, "online")
	for _, filter := range []string{h.cfg.BaseTopic + "/+/set/+", h.cfg.BaseTopic + "/+/set_hvac/+"} {
		c.Subscribe(filter, 1, func(_ paho.Client, m paho.Message) { h.onCommand(ctx, m.Topic(), string(m.Payload())) })
	}
	go h.sync(ctx, "", "")
}

// sync publishes discovery for new devices and state/availability for one or all devices.
func (h *Publisher) sync(ctx context.Context, profileID, key string) {
	if h.client == nil || !h.client.IsConnected() {
		return
	}
	devs, err := h.eng.Devices(ctx)
	if err != nil {
		h.log.Error("list devices", "err", err)
		return
	}
	for _, d := range devs {
		if profileID != "" && (d.Profile != profileID || d.Key != key) {
			continue
		}
		p, ok := h.eng.Profile(d.Profile)
		if !ok {
			continue
		}
		slug := Slug(d.Profile, d.Key)
		t := NewTopics(h.cfg.BaseTopic, slug)
		h.mu.Lock()
		_, seen := h.known[slug]
		h.known[slug] = d
		wasOnline, hadAvail := h.online[slug]
		h.online[slug] = d.Online
		h.mu.Unlock()
		if !seen {
			for _, m := range DiscoveryMessages(h.cfg.DiscoveryPrefix, h.cfg.BaseTopic, d, p.Profile) {
				h.publish(m.Topic, m.Payload, true)
			}
			h.log.Info("discovery published", "device", d.ID, "entities", len(p.HomeAssistant.Entities))
		}
		if !hadAvail || wasOnline != d.Online {
			avail := "offline"
			if d.Online {
				avail = "online"
			}
			h.publish(t.Availability, []byte(avail), true)
		}
		h.publish(t.State, StatePayload(p.Profile, d.State), true)
	}
}

func (h *Publisher) onCommand(ctx context.Context, topic, payload string) {
	parts := strings.Split(strings.TrimPrefix(topic, h.cfg.BaseTopic+"/"), "/")
	if len(parts) != 3 {
		return
	}
	h.mu.Lock()
	d, ok := h.known[parts[0]]
	h.mu.Unlock()
	if !ok {
		h.log.Warn("command for unknown device", "topic", topic)
		return
	}
	p, ok := h.eng.Profile(d.Profile)
	if !ok {
		return
	}
	variable, value, ok := ParseCommand(p.Profile, NewTopics(h.cfg.BaseTopic, parts[0]), topic, payload)
	if !ok {
		h.log.Warn("unsupported Home Assistant command", "topic", topic, "payload", payload)
		return
	}
	if _, err := h.eng.SendCommand(ctx, d.Profile, d.Key, variable, "", value); err != nil {
		h.log.Warn("Home Assistant command failed", "device", d.ID, "variable", variable, "err", err)
	}
}
