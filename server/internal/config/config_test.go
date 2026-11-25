package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(path, []byte("http:\n  listen: [\"127.0.0.1:8081\"]\nhome_assistant:\n  broker: tcp://ha:1883\nenrolled:\n  - {name: plug, ip: 10.0.0.2}\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.API.Listen != "127.0.0.1:8080" || c.HomeAssistant.DiscoveryPrefix != "homeassistant" || c.HomeAssistant.BaseTopic != "modigliani" {
		t.Errorf("defaults %+v", c)
	}
	if c.HTTP.TLSListen != nil || c.MQTT != nil {
		t.Error("a present section is used as written; absent sections stay nil")
	}
	if !c.IsEnrolled("10.0.0.2") || c.IsEnrolled("10.0.0.3") {
		t.Error("enrollment")
	}
	if !(&Config{}).IsEnrolled("anything") {
		t.Error("without enrollment every client is served")
	}
	example, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil || example.HTTP == nil || len(example.Enrolled) != 1 {
		t.Errorf("config.example.yaml must load: %v %+v", err, example)
	}
	_ = os.WriteFile(path, []byte("htttp: {}\n"), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("typos in the config are errors")
	}
}
