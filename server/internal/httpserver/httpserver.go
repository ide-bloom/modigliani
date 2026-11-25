// Package httpserver answers devices over HTTP, HTTPS and WebSocket using profile handlers.
package httpserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

const maxBody = 1 << 20

// Server serves the HTTP side of every loaded profile.
type Server struct {
	eng *engine.Engine
	cfg *config.Config
	log *slog.Logger
}

// New creates the server.
func New(eng *engine.Engine, cfg *config.Config, log *slog.Logger) *Server {
	return &Server{eng: eng, cfg: cfg, log: log.With("component", "http")}
}

// Run listens on plain and TLS addresses until ctx is cancelled.
func (s *Server) Run(ctx context.Context, plain, secure []string, tlsConf *tls.Config) error {
	errs := make(chan error, len(plain)+len(secure))
	var servers []*http.Server
	start := func(addr string, tc *tls.Config) error {
		var lc net.ListenConfig
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		srv := &http.Server{Handler: s, ReadHeaderTimeout: 15 * time.Second, TLSConfig: tc,
			ErrorLog: slog.NewLogLogger(s.log.Handler(), slog.LevelDebug)}
		servers = append(servers, srv)
		go func() {
			var err error
			if tc != nil {
				err = srv.ServeTLS(ln, "", "")
			} else {
				err = srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
		s.log.Info("listening", "addr", ln.Addr().String(), "tls", tc != nil)
		return nil
	}
	for _, a := range plain {
		if err := start(a, nil); err != nil {
			return err
		}
	}
	for _, a := range secure {
		if tlsConf == nil {
			return errors.New("TLS listener configured but no local CA is loaded")
		}
		if err := start(a, tlsConf); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
	case err := <-errs:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx) //nolint:contextcheck // shutdown must outlive the cancelled ctx
	}
	return nil
}

func remoteIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host)
}

func hostMatches(handlerHost, host string) bool {
	if handlerHost == "" || host == "" || net.ParseIP(host) != nil || net.ParseIP(handlerHost) != nil {
		return true
	}
	return strings.EqualFold(handlerHost, host)
}

type match struct {
	p      *engine.Loaded
	h      *profile.HTTPHandler
	params map[string]string
}

func (s *Server) find(r *http.Request) (match, bool) {
	host := requestHost(r)
	var fallback *match
	for _, p := range s.eng.Profiles() {
		for i := range p.Handlers.HTTP {
			h := &p.Handlers.HTTP[i]
			if !strings.EqualFold(h.Method, r.Method) {
				continue
			}
			params, ok := profile.MatchTemplate(h.Path, r.URL.Path, "/")
			if !ok || !hostMatches(h.Host, host) {
				continue
			}
			m := match{p, h, params}
			if h.Host != "" && strings.EqualFold(h.Host, host) {
				return m, true
			}
			if fallback == nil {
				fallback = &m
			}
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return match{}, false
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := remoteIP(r.RemoteAddr)
	if !s.cfg.IsEnrolled(ip) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		if s.serveWebSocket(w, r, ip) {
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m, ok := s.find(r)
	if !ok {
		s.unhandled(ctx, w, r, ip, body)
		return
	}
	req := map[string]any{
		"path":   toAny(m.params),
		"query":  firstValues(r.URL.Query()),
		"header": headerMap(r.Header),
		"body":   parseBody(r.Header.Get("Content-Type"), body),
	}
	p, h := m.p, m.h
	key := ""
	if h.Identity != "" {
		if v, ok := tmpl.Lookup(h.Identity, &tmpl.Context{Req: req}); ok && v != nil {
			key = tmpl.Text(v)
		}
	}
	if h.Auth == "token" {
		tokenKey, valid := s.eng.CheckToken(ctx, p, presentedToken(p.Auth.Token, r, req))
		if !valid {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if key == "" {
			key = tokenKey
		}
	}
	if key == "" && len(h.Extract) > 0 {
		key = ip
	}
	// Anonymous housekeeping (time, firmware checks) is answered without registering a device.
	if key != "" {
		s.eng.Touch(ctx, p, key, ip, m.params)
		s.eng.ApplyExtracts(ctx, p, key, h.Extract, req)
	}
	tctx := s.eng.Context(ctx, p, key, req)
	if h.Auth == "issue_token" {
		tok, err := s.eng.IssueToken(ctx, p, key)
		if err != nil {
			s.log.Error("issue token", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		tctx.Token = tok
	}
	out := tmpl.Render(h.Response.Body, tctx)
	if h.DeliversCommands != nil {
		out = s.deliver(ctx, p, key, h, out, tctx)
	}
	s.write(w, h.Response, out)
}

func (s *Server) deliver(ctx context.Context, p *engine.Loaded, key string, h *profile.HTTPHandler, body any, tctx *tmpl.Context) any {
	cmds := s.eng.TakeCommands(ctx, p, key, h.ID)
	if len(cmds) == 0 {
		return body
	}
	items := make([]any, 0, len(cmds))
	for _, qc := range cmds {
		cmd, ok := p.CommandByName(qc.Name)
		if !ok {
			continue
		}
		items = append(items, s.eng.RenderCommand(cmd, p, qc.Value, qc.ID, tctx))
	}
	s.log.Info("delivered commands", "profile", p.ID, "device", key, "count", len(items))
	if h.DeliversCommands.Mode == "replace" {
		return tmpl.SetPath(body, h.DeliversCommands.Path, items[0])
	}
	return tmpl.SetPath(body, h.DeliversCommands.Path, items)
}

func (s *Server) write(w http.ResponseWriter, spec profile.HTTPResponse, body any) {
	status := spec.Status
	if status == 0 {
		status = http.StatusOK
	}
	for k, v := range spec.Headers {
		if !strings.EqualFold(k, "content-length") {
			w.Header().Set(k, v)
		}
	}
	switch spec.BodyType {
	case "empty":
		w.WriteHeader(status)
	case "text":
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/plain")
		}
		w.WriteHeader(status)
		// Text bodies go to devices, rendered from the profile's own templates.
		_, _ = io.WriteString(w, tmpl.Text(body)) //nolint:gosec // not a browser-facing page
	case "form":
		vals := url.Values{}
		if m, ok := body.(map[string]any); ok {
			for k, v := range m {
				vals.Set(k, tmpl.Text(v))
			}
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, vals.Encode())
	default:
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		writeJSON(w, status, body)
	}
}

func (s *Server) unhandled(ctx context.Context, w http.ResponseWriter, r *http.Request, ip string, body []byte) {
	summary := fmt.Sprintf("%s %s%s", r.Method, requestHost(r), r.URL.RequestURI())
	detail, _ := json.Marshal(map[string]any{"headers": headerMap(r.Header), "body": string(body)})
	s.eng.Unhandled(ctx, "http", ip, summary, string(detail))
	spec := profile.HTTPResponse{Status: http.StatusOK, BodyType: "json", Body: map[string]any{}}
	host := requestHost(r)
	for _, p := range s.eng.Profiles() {
		for _, n := range p.Hostnames() {
			if n == host {
				spec = p.Defaults.HTTP
			}
		}
	}
	s.write(w, spec, spec.Body)
}

func presentedToken(spec *profile.TokenSpec, r *http.Request, req map[string]any) string {
	if spec == nil {
		return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	switch spec.Location {
	case "header":
		return r.Header.Get(spec.Name)
	case "query":
		return r.URL.Query().Get(spec.Name)
	case "body":
		if v, ok := tmpl.GetPath(req["body"], spec.Name); ok {
			return tmpl.Text(v)
		}
		return ""
	default:
		auth := r.Header.Get("Authorization")
		if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
			return strings.TrimSpace(auth[7:])
		}
		return strings.TrimSpace(auth)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func toAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func firstValues(q url.Values) map[string]any {
	out := make(map[string]any, len(q))
	for k, v := range q {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func headerMap(h http.Header) map[string]any {
	out := make(map[string]any, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

func parseBody(contentType string, body []byte) any {
	if len(body) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	trimmed := strings.TrimSpace(string(body))
	if strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			return v
		}
	}
	if strings.Contains(ct, "x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(string(body)); err == nil {
			return firstValues(vals)
		}
	}
	return string(body)
}

// serveWebSocket handles upgrades for profile WebSocket handlers; false means "not ours".
func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request, ip string) bool {
	host := requestHost(r)
	for _, p := range s.eng.Profiles() {
		for i := range p.Handlers.WebSocket {
			h := &p.Handlers.WebSocket[i]
			params, ok := profile.MatchTemplate(h.Path, r.URL.Path, "/")
			if !ok || !hostMatches(h.Host, host) {
				continue
			}
			s.runWebSocket(w, r, ip, p, h, params)
			return true
		}
	}
	return false
}

func (s *Server) runWebSocket(w http.ResponseWriter, r *http.Request, ip string, p *engine.Loaded, h *profile.WebSocketHandler, params map[string]string) {
	// Devices do not send browser Origin headers worth checking; access is limited by enrollment.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	ctx := r.Context()
	key := ip
	if h.Identity != "" {
		if v, ok := tmpl.Lookup(h.Identity, &tmpl.Context{Req: map[string]any{"path": toAny(params)}}); ok && v != nil {
			key = tmpl.Text(v)
		}
	}
	s.eng.Touch(ctx, p, key, ip, params)
	// Commands may be pushed at any time while the device stays connected.
	sendCtx := context.WithoutCancel(ctx)
	unregister := s.eng.RegisterSender(p.ID, key, func(payload []byte) error {
		wctx, cancel := context.WithTimeout(sendCtx, 5*time.Second)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, payload)
	})
	defer unregister()
	defer func() { _ = conn.CloseNow() }()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var msg map[string]any
		if json.Unmarshal(data, &msg) != nil {
			s.eng.Unhandled(ctx, "websocket", ip, h.Path, string(data))
			continue
		}
		rule := matchRule(h.Messages, msg)
		if rule == nil {
			s.eng.Unhandled(ctx, "websocket", ip, h.Path, string(data))
			continue
		}
		req := map[string]any{"path": toAny(params), "payload": msg}
		s.eng.Touch(ctx, p, key, ip, params)
		s.eng.ApplyExtracts(ctx, p, key, rule.Extract, req)
		if rule.Reply != nil {
			out, err := json.Marshal(tmpl.Render(rule.Reply, s.eng.Context(ctx, p, key, req)))
			if err == nil {
				_ = conn.Write(ctx, websocket.MessageText, out)
			}
		}
	}
}

func matchRule(rules []profile.WSMessageRule, msg map[string]any) *profile.WSMessageRule {
	for i := range rules {
		ok := true
		for k, want := range rules[i].Match {
			if tmpl.Text(msg[k]) != tmpl.Text(want) {
				ok = false
				break
			}
		}
		if ok {
			return &rules[i]
		}
	}
	return nil
}
