// Package api serves the local REST + WebSocket API and the status page, protected by a token.
package api

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/logging"
)

//go:embed status.html
var statusPage []byte

// Server is the local API.
type Server struct {
	eng     *engine.Engine
	token   string
	log     *slog.Logger
	ring    *logging.Ring
	version string
}

// New creates the API server.
func New(eng *engine.Engine, token string, log *slog.Logger, ring *logging.Ring, version string) *Server {
	return &Server{eng: eng, token: token, log: log.With("component", "api"), ring: ring, version: version}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self' ws: wss:")
		_, _ = w.Write(statusPage)
	})
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.version, "profiles": len(s.eng.Profiles())})
	})
	mux.Handle("GET /api/devices", s.auth(http.HandlerFunc(s.devices)))
	mux.Handle("GET /api/devices/{profile}/{key}", s.auth(http.HandlerFunc(s.device)))
	mux.Handle("POST /api/devices/{profile}/{key}/commands", s.auth(http.HandlerFunc(s.command)))
	mux.Handle("GET /api/profiles", s.auth(http.HandlerFunc(s.profiles)))
	mux.Handle("GET /api/unhandled", s.auth(http.HandlerFunc(s.unhandled)))
	mux.Handle("GET /api/logs", s.auth(http.HandlerFunc(s.logs)))
	mux.Handle("GET /api/events", s.auth(http.HandlerFunc(s.events)))
	return mux
}

// Run listens until ctx is cancelled.
func (s *Server) Run(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(ln) }()
	s.log.Info("local API and status page", "url", "http://"+ln.Addr().String()+"/")
	select {
	case <-ctx.Done():
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx) //nolint:contextcheck // shutdown must outlive the cancelled ctx
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			// Browsers cannot set headers on WebSocket requests.
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or wrong API token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.eng.Devices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, devs)
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	devs, err := s.eng.Devices(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, d := range devs {
		if d.Profile == r.PathValue("profile") && d.Key == r.PathValue("key") {
			writeJSON(w, http.StatusOK, d)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown device"})
}

type commandRequest struct {
	Variable string `json:"variable"`
	Command  string `json:"command"`
	Value    any    `json:"value"`
}

func (s *Server) command(w http.ResponseWriter, r *http.Request) {
	var req commandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON: {\"variable\": ..., \"value\": ...}"})
		return
	}
	if req.Variable == "" && req.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "set variable or command"})
		return
	}
	res, err := s.eng.SendCommand(r.Context(), r.PathValue("profile"), r.PathValue("key"), req.Variable, req.Command, req.Value)
	if errors.Is(err, engine.ErrUnknownDevice) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) profiles(w http.ResponseWriter, _ *http.Request) {
	type view struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Path      string   `json:"path"`
		Signature string   `json:"signature"`
		Library   bool     `json:"library"`
		Hostnames []string `json:"hostnames"`
	}
	out := []view{}
	for _, p := range s.eng.Profiles() {
		out = append(out, view{p.ID, p.Name, p.Path, p.Signature.Status, p.Library, p.Hostnames()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) unhandled(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	items, err := s.eng.Store().ListUnhandled(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) logs(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.ring.Records())
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()
	ctx := conn.CloseRead(r.Context())
	events, cancel := s.eng.Subscribe()
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			if conn.Write(ctx, websocket.MessageText, data) != nil {
				return
			}
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
