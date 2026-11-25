// Command modigliani-server is the generic replacement cloud: it loads device profiles and
// answers devices in place of their vendor's servers.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ide-bloom/modigliani/server/internal/api"
	"github.com/ide-bloom/modigliani/server/internal/ca"
	"github.com/ide-bloom/modigliani/server/internal/coapserver"
	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/dnsserver"
	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/hass"
	"github.com/ide-bloom/modigliani/server/internal/httpserver"
	"github.com/ide-bloom/modigliani/server/internal/logging"
	"github.com/ide-bloom/modigliani/server/internal/mqttserver"
	"github.com/ide-bloom/modigliani/server/internal/rawserver"
	"github.com/ide-bloom/modigliani/server/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "modigliani-server:", err)
		os.Exit(1)
	}
}

func run() error {
	var profiles multiFlag
	fs := flag.NewFlagSet("modigliani-server", flag.ContinueOnError)
	fs.Var(&profiles, "profiles", "profile file or directory (repeatable)")
	configPath := fs.String("config", "", "configuration file (YAML or JSON)")
	logFormat := fs.String("log-format", "text", "text or json")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("modigliani-server", version)
		return nil
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ring := logging.NewRing(500)
	log, err := logging.New(os.Stderr, cfg.LogLevel, *logFormat, ring)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	paths := append(append([]string{}, profiles...), cfg.Profiles...)
	if len(paths) == 0 {
		return errors.New("no profiles: pass --profiles <dir>")
	}
	loaded, err := engine.LoadProfiles(log, paths, cfg.TrustedKeys)
	if err != nil {
		return err
	}
	if len(loaded) == 0 {
		return errors.New("no usable profiles were loaded")
	}
	st, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	eng := engine.New(log, st, loaded, engine.Options{
		TimeOffset:    time.Duration(cfg.TimeOffsetS * float64(time.Second)),
		DeviceTimeout: time.Duration(cfg.DeviceTimeoutS) * time.Second,
	})
	token, err := apiToken(cfg, log)
	if err != nil {
		return err
	}

	needs := needed(loaded)
	tlsConf, err := tlsConfig(cfg, loaded, needs, log)
	if err != nil {
		return err
	}
	applyDefaults(cfg, needs, tlsConf != nil)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return api.New(eng, token, log, ring, version).Run(gctx, cfg.API.Listen) })
	if cfg.HTTP != nil && (len(cfg.HTTP.Listen)+len(cfg.HTTP.TLSListen)) > 0 {
		g.Go(func() error {
			return httpserver.New(eng, cfg, log).Run(gctx, cfg.HTTP.Listen, cfg.HTTP.TLSListen, tlsConf)
		})
	}
	if cfg.MQTT != nil && (len(cfg.MQTT.Listen)+len(cfg.MQTT.TLSListen)) > 0 {
		g.Go(func() error {
			return mqttserver.New(eng, cfg, log).Run(gctx, cfg.MQTT.Listen, cfg.MQTT.TLSListen, tlsConf)
		})
	}
	if cfg.CoAP != nil && len(cfg.CoAP.Listen) > 0 {
		g.Go(func() error { return coapserver.New(eng, cfg, log).Run(gctx, cfg.CoAP.Listen) })
	}
	if needs.raw {
		g.Go(func() error { return rawserver.New(eng, cfg, log).Run(gctx) })
	}
	if cfg.DNS != nil && cfg.DNS.Listen != "" {
		var names []string
		for _, p := range loaded {
			names = append(names, p.Hostnames()...)
		}
		g.Go(func() error { return dnsserver.New(cfg, log, names).Run(gctx) })
	}
	if cfg.HomeAssistant != nil && cfg.HomeAssistant.Broker != "" {
		g.Go(func() error { return hass.NewPublisher(cfg.HomeAssistant, eng, log).Run(gctx) })
	}
	log.Info("Modigliani Server started", "version", version, "profiles", len(loaded))
	return g.Wait()
}

type needs struct{ http, mqtt, coap, raw, tls bool }

func needed(profiles []*engine.Loaded) needs {
	var n needs
	for _, p := range profiles {
		n.http = n.http || len(p.Handlers.HTTP) > 0 || len(p.Handlers.WebSocket) > 0
		n.mqtt = n.mqtt || p.Handlers.MQTT != nil
		n.coap = n.coap || len(p.Handlers.CoAP) > 0
		n.raw = n.raw || len(p.Handlers.Raw) > 0
		n.tls = n.tls || p.TLS.Mode == "local_ca" || p.TLS.Mode == "mixed"
	}
	return n
}

// applyDefaults fills listeners for protocols the profiles need when the config file did
// not mention them at all.
func applyDefaults(cfg *config.Config, n needs, haveTLS bool) {
	if cfg.HTTP == nil && n.http {
		cfg.HTTP = &config.Listeners{Listen: []string{":80"}}
		if haveTLS {
			cfg.HTTP.TLSListen = []string{":443"}
		}
	}
	if cfg.MQTT == nil && n.mqtt {
		cfg.MQTT = &config.Listeners{Listen: []string{":1883"}}
		if haveTLS {
			cfg.MQTT.TLSListen = []string{":8883"}
		}
	}
	if cfg.CoAP == nil && n.coap {
		cfg.CoAP = &config.Listeners{Listen: []string{":5683"}}
	}
}

func tlsConfig(cfg *config.Config, profiles []*engine.Loaded, n needs, log *slog.Logger) (*tls.Config, error) {
	wantTLS := (cfg.HTTP != nil && len(cfg.HTTP.TLSListen) > 0) || (cfg.MQTT != nil && len(cfg.MQTT.TLSListen) > 0)
	defaultsNeedTLS := n.tls && (cfg.HTTP == nil || cfg.MQTT == nil)
	if !wantTLS && !defaultsNeedTLS {
		return nil, nil
	}
	authority, err := ca.Load(cfg.CADir)
	if err != nil {
		if wantTLS {
			return nil, err
		}
		log.Warn("no local CA: TLS listeners are disabled", "err", err)
		return nil, nil
	}
	fallback := ""
	for _, p := range profiles {
		names := p.Hostnames()
		authority.Allow(names...)
		if fallback == "" && len(p.TLS.Hostnames) > 0 {
			fallback = p.TLS.Hostnames[0]
		}
	}
	return authority.TLSConfig(fallback), nil
}

func apiToken(cfg *config.Config, log *slog.Logger) (string, error) {
	if cfg.API.Token != "" {
		return cfg.API.Token, nil
	}
	path := cfg.API.TokenFile
	if path == "" {
		path = filepath.Join(cfg.DataDir, "api-token")
	}
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // operator-chosen file
		return strings.TrimSpace(string(data)), nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	log.Info("generated a local API token", "file", path)
	return token, nil
}
