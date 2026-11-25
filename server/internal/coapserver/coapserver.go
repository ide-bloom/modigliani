// Package coapserver answers devices over CoAP/UDP (go-coap), including binary frame payloads.
package coapserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/mux"
	coapnet "github.com/plgd-dev/go-coap/v3/net"
	"github.com/plgd-dev/go-coap/v3/options"
	"github.com/plgd-dev/go-coap/v3/udp"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/frame"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/tmpl"
)

// Server serves every profile's CoAP resources.
type Server struct {
	eng *engine.Engine
	cfg *config.Config
	log *slog.Logger
}

// New creates the server.
func New(eng *engine.Engine, cfg *config.Config, log *slog.Logger) *Server {
	return &Server{eng: eng, cfg: cfg, log: log.With("component", "coap")}
}

// Response is a rendered CoAP answer.
type Response struct {
	Code    codes.Code
	Format  message.MediaType
	Payload []byte
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context, addrs []string) error {
	router := mux.NewRouter()
	router.DefaultHandle(mux.HandlerFunc(func(w mux.ResponseWriter, r *mux.Message) {
		path, _ := r.Path()
		body, _ := r.ReadBody()
		ip := ""
		if addr, ok := w.Conn().RemoteAddr().(*net.UDPAddr); ok {
			ip = addr.IP.String()
		}
		resp, ok := s.Handle(ctx, ip, r.Code().String(), path, body)
		if !ok {
			return
		}
		if err := w.SetResponse(resp.Code, resp.Format, bytes.NewReader(resp.Payload)); err != nil {
			s.log.Warn("coap response", "err", err)
		}
	}))
	var servers []interface{ Stop() }
	for _, a := range addrs {
		l, err := coapnet.NewListenUDP("udp", a)
		if err != nil {
			return err
		}
		srv := udp.NewServer(options.WithMux(router))
		servers = append(servers, srv)
		go func() {
			if err := srv.Serve(l); err != nil {
				s.log.Error("coap serve", "addr", a, "err", err)
			}
		}()
		s.log.Info("listening", "addr", a)
	}
	<-ctx.Done()
	for _, srv := range servers {
		srv.Stop()
	}
	return nil
}

// Handle answers one request; ok is false when the client is not served at all.
func (s *Server) Handle(ctx context.Context, ip, method, path string, body []byte) (Response, bool) {
	if !s.cfg.IsEnrolled(ip) {
		return Response{}, false
	}
	for _, p := range s.eng.Profiles() {
		for i := range p.Handlers.CoAP {
			h := &p.Handlers.CoAP[i]
			if !strings.EqualFold(h.Method, method) {
				continue
			}
			params, ok := profile.MatchTemplate(h.Path, path, "/")
			if !ok {
				continue
			}
			return s.answer(ctx, ip, p, h, params, body), true
		}
	}
	s.eng.Unhandled(ctx, "coap", ip, method+" "+path, fmt.Sprintf("%x", body))
	return Response{Code: codes.NotFound, Format: message.TextPlain}, true
}

func (s *Server) answer(ctx context.Context, ip string, p *engine.Loaded, h *profile.CoAPHandler, params map[string]string, body []byte) Response {
	req := map[string]any{"path": toAny(params)}
	if h.RequestFrame != "" {
		layout, ok := p.Frame(h.RequestFrame)
		if !ok {
			return Response{Code: codes.InternalServerError, Format: message.TextPlain}
		}
		fields, err := frame.Decode(body, layout)
		if err != nil {
			s.eng.Unhandled(ctx, "coap", ip, h.Method+" "+h.Path+": "+err.Error(), fmt.Sprintf("%x", body))
			return Response{Code: codes.BadRequest, Format: message.TextPlain}
		}
		req["fields"] = fields
	} else if len(body) > 0 {
		var v any
		if json.Unmarshal(body, &v) == nil {
			req["payload"] = v
		} else {
			req["payload"] = string(body)
		}
	}
	key := ""
	if h.Identity != "" {
		if v, ok := tmpl.Lookup(h.Identity, &tmpl.Context{Req: req}); ok && v != nil {
			key = tmpl.Text(v)
		}
	}
	if key == "" && len(h.Extract) > 0 {
		key = ip
	}
	if key != "" {
		s.eng.Touch(ctx, p, key, ip, params)
		s.eng.ApplyExtracts(ctx, p, key, h.Extract, req)
	}
	tctx := s.eng.Context(ctx, p, key, req)
	code := parseCode(h.Response.Code)
	switch h.Response.PayloadType {
	case "frame":
		if h.Response.Frame == nil {
			return Response{Code: code, Format: message.AppOctets}
		}
		layout, ok := p.Frame(h.Response.Frame.Frame)
		if !ok {
			return Response{Code: codes.InternalServerError, Format: message.TextPlain}
		}
		values := map[string]any{}
		for name, t := range h.Response.Frame.Values {
			values[name] = tmpl.Render(t, tctx)
		}
		out, err := frame.Encode(layout, values)
		if err != nil {
			s.log.Error("encode frame", "frame", layout.ID, "err", err)
			return Response{Code: codes.InternalServerError, Format: message.TextPlain}
		}
		return Response{Code: code, Format: format(h.Response.ContentFormat, message.AppOctets), Payload: out}
	case "json":
		out, err := json.Marshal(tmpl.Render(h.Response.Payload, tctx))
		if err != nil {
			return Response{Code: codes.InternalServerError, Format: message.TextPlain}
		}
		return Response{Code: code, Format: format(h.Response.ContentFormat, message.AppJSON), Payload: out}
	case "text":
		return Response{Code: code, Format: format(h.Response.ContentFormat, message.TextPlain),
			Payload: []byte(tmpl.Text(tmpl.Render(h.Response.Payload, tctx)))}
	default:
		return Response{Code: code, Format: format(h.Response.ContentFormat, message.TextPlain)}
	}
}

func format(cf *int, fallback message.MediaType) message.MediaType {
	if cf != nil {
		return message.MediaType(*cf) //nolint:gosec // content formats are 16-bit by spec
	}
	return fallback
}

// parseCode turns "2.04" into a CoAP code.
func parseCode(s string) codes.Code {
	class, detail, ok := strings.Cut(s, ".")
	if !ok {
		return codes.Content
	}
	c, err1 := strconv.Atoi(class)
	d, err2 := strconv.Atoi(detail)
	if err1 != nil || err2 != nil {
		return codes.Content
	}
	return codes.Code(c<<5 | d) //nolint:gosec // class and detail are small by spec
}

func toAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
