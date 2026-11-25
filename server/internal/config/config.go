// Package config reads the server configuration file (YAML or JSON).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// Listeners for one protocol. A nil section means "use defaults if a profile needs it";
// a present section is used exactly as written.
type Listeners struct {
	Listen    []string `json:"listen"`
	TLSListen []string `json:"tls_listen"`
}

// Enrolled is a device the operator confirmed they own.
type Enrolled struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
}

// API configures the local API and status page.
type API struct {
	Listen    string `json:"listen"`
	Token     string `json:"token"`
	TokenFile string `json:"token_file"`
}

// DNS configures the optional DNS responder (router and gateway mode).
type DNS struct {
	Listen   string `json:"listen"`
	AnswerIP string `json:"answer_ip"`
	Upstream string `json:"upstream"`
}

// HomeAssistant configures MQTT discovery to the user's broker.
type HomeAssistant struct {
	Broker          string `json:"broker"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	ClientID        string `json:"client_id"`
	DiscoveryPrefix string `json:"discovery_prefix"`
	BaseTopic       string `json:"base_topic"`
}

// Raw maps "tcp/9000"-style handler keys to listen addresses.
type Raw struct {
	Listen map[string]string `json:"listen"`
}

// Config is the whole server configuration.
type Config struct {
	DataDir        string         `json:"data_dir"`
	CADir          string         `json:"ca_dir"`
	Profiles       []string       `json:"profiles"`
	API            API            `json:"api"`
	HTTP           *Listeners     `json:"http"`
	MQTT           *Listeners     `json:"mqtt"`
	CoAP           *Listeners     `json:"coap"`
	Raw            Raw            `json:"raw"`
	DNS            *DNS           `json:"dns"`
	Enrolled       []Enrolled     `json:"enrolled"`
	TrustedKeys    []string       `json:"trusted_keys"`
	HomeAssistant  *HomeAssistant `json:"home_assistant"`
	TimeOffsetS    float64        `json:"time_offset_s"`
	DeviceTimeoutS int            `json:"device_timeout_s"`
	LogLevel       string         `json:"log_level"`
}

// Defaults fills unset values.
func (c *Config) Defaults() {
	if c.DataDir == "" {
		c.DataDir = "modigliani-data"
	}
	if c.CADir == "" {
		c.CADir = "ca"
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:8080"
	}
	if c.DeviceTimeoutS == 0 {
		c.DeviceTimeoutS = 120
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.HomeAssistant != nil {
		if c.HomeAssistant.DiscoveryPrefix == "" {
			c.HomeAssistant.DiscoveryPrefix = "homeassistant"
		}
		if c.HomeAssistant.BaseTopic == "" {
			c.HomeAssistant.BaseTopic = "modigliani"
		}
		if c.HomeAssistant.ClientID == "" {
			host, _ := os.Hostname()
			c.HomeAssistant.ClientID = "modigliani-server-" + host
		}
	}
	if c.DNS != nil && c.DNS.Upstream == "" {
		c.DNS.Upstream = "1.1.1.1:53"
	}
}

// Load reads a config file; an empty path yields defaults.
func Load(path string) (*Config, error) {
	c := &Config{}
	if path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-chosen file
		if err != nil {
			return nil, err
		}
		var generic any
		if filepath.Ext(path) == ".json" {
			err = json.Unmarshal(data, &generic)
		} else {
			err = yaml.Unmarshal(data, &generic)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		enc, err := json.Marshal(generic)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(enc))
		dec.DisallowUnknownFields()
		if err := dec.Decode(c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	c.Defaults()
	return c, nil
}

// IsEnrolled reports whether a client address may be served. With no enrolled devices
// every client is served (bind to loopback or a dedicated interface in that case); the
// DNS responder, however, always requires enrollment.
func (c *Config) IsEnrolled(ip string) bool {
	if len(c.Enrolled) == 0 {
		return true
	}
	for _, e := range c.Enrolled {
		if e.IP == ip {
			return true
		}
	}
	return false
}
