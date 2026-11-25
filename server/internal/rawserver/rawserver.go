// Package rawserver answers devices that speak raw TCP or UDP with framed binary messages.
package rawserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/frame"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// Server runs one listener per raw handler.
type Server struct {
	eng *engine.Engine
	cfg *config.Config
	log *slog.Logger
}

// New creates the server.
func New(eng *engine.Engine, cfg *config.Config, log *slog.Logger) *Server {
	return &Server{eng: eng, cfg: cfg, log: log.With("component", "raw")}
}

// Key identifies a raw handler in the config's raw.listen map, e.g. "tcp/9000".
func Key(h profile.RawHandler) string { return h.Transport + "/" + strconv.Itoa(h.Port) }

// Run starts every raw handler's listener until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for _, p := range s.eng.Profiles() {
		for i := range p.Handlers.Raw {
			h := &p.Handlers.Raw[i]
			addr := s.cfg.Raw.Listen[Key(*h)]
			if addr == "" {
				addr = ":" + strconv.Itoa(h.Port)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				if h.Transport == "udp" {
					err = s.serveUDP(ctx, addr, p, h)
				} else {
					err = s.serveTCP(ctx, addr, p, h)
				}
				if err != nil {
					errs <- err
				}
			}()
		}
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case err := <-errs:
		return err
	}
}

// Process handles one frame and returns the reply frame (nil for none).
func (s *Server) Process(ctx context.Context, ip string, p *engine.Loaded, h *profile.RawHandler, msg []byte) ([]byte, string) {
	for _, rule := range h.Rules {
		layout, ok := p.Frame(rule.Frame)
		if !ok || !frame.MatchRule(msg, layout, rule.Match) {
			continue
		}
		fields, err := frame.Decode(msg, layout)
		if err != nil {
			s.eng.Unhandled(ctx, "raw", ip, h.ID+": "+err.Error(), fmt.Sprintf("%x", msg))
			return nil, ""
		}
		req := map[string]any{"fields": fields}
		key := ip
		if h.Identity != "" {
			if v, ok := tmpl.Lookup(h.Identity, &tmpl.Context{Req: req}); ok && v != nil {
				key = tmpl.Text(v)
			}
		}
		s.eng.Touch(ctx, p, key, ip, nil)
		s.eng.ApplyExtracts(ctx, p, key, rule.Extract, req)
		if rule.Reply == nil {
			return nil, key
		}
		rl, ok := p.Frame(rule.Reply.Frame)
		if !ok {
			return nil, key
		}
		tctx := s.eng.Context(ctx, p, key, req)
		values := map[string]any{}
		for name, t := range rule.Reply.Values {
			values[name] = tmpl.Render(t, tctx)
		}
		out, err := frame.Encode(rl, values)
		if err != nil {
			s.log.Error("encode reply", "frame", rl.ID, "err", err)
			return nil, key
		}
		return frame.Join(out, h.Framing), key
	}
	s.eng.Unhandled(ctx, "raw", ip, h.ID+": no rule matches", fmt.Sprintf("%x", msg))
	return nil, ""
}

func (s *Server) serveTCP(ctx context.Context, addr string, p *engine.Loaded, h *profile.RawHandler) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	s.log.Info("listening", "addr", ln.Addr().String(), "handler", h.ID)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn, p, h)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn, p *engine.Loaded, h *profile.RawHandler) {
	defer func() { _ = conn.Close() }()
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !s.cfg.IsEnrolled(ip) {
		return
	}
	var unregister func()
	defer func() {
		if unregister != nil {
			unregister()
		}
	}()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err := conn.Read(chunk)
		if err != nil {
			return
		}
		buf = append(buf, chunk[:n]...)
		var frames [][]byte
		frames, buf = frame.Split(buf, h.Framing)
		if h.Framing.Kind == "datagram" || h.Framing.Kind == "" {
			buf = buf[:0]
		}
		for _, f := range frames {
			reply, key := s.Process(ctx, ip, p, h, f)
			if key != "" && unregister == nil {
				unregister = s.eng.RegisterSender(p.ID, key, func(b []byte) error {
					_, err := conn.Write(frame.Join(b, h.Framing))
					return err
				})
			}
			if reply != nil {
				if _, err := conn.Write(reply); err != nil {
					return
				}
			}
		}
	}
}

func (s *Server) serveUDP(ctx context.Context, addr string, p *engine.Loaded, h *profile.RawHandler) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		return err
	}
	s.log.Info("listening", "addr", pc.LocalAddr().String(), "handler", h.ID)
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		ip, _, _ := net.SplitHostPort(from.String())
		if !s.cfg.IsEnrolled(ip) {
			continue
		}
		msg := append([]byte(nil), buf[:n]...)
		if reply, _ := s.Process(ctx, ip, p, h, msg); reply != nil {
			_, _ = pc.WriteTo(reply, from)
		}
	}
}
