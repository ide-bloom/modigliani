// Package dnsserver answers enrolled devices' DNS queries for vendor hostnames with this
// server's address (router and gateway mode). Everyone else is refused.
package dnsserver

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ide-bloom/modigliani/server/internal/config"
)

// Server is the DNS responder.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	names    map[string]bool
	answer   net.IP
	upstream string
	exchange func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error)
}

// New builds a responder for the given hostnames.
func New(cfg *config.Config, log *slog.Logger, hostnames []string) *Server {
	names := map[string]bool{}
	for _, n := range hostnames {
		names[dns.Fqdn(strings.ToLower(n))] = true
	}
	s := &Server{cfg: cfg, log: log.With("component", "dns"), names: names, upstream: cfg.DNS.Upstream,
		answer: net.ParseIP(cfg.DNS.AnswerIP)}
	s.exchange = func(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		c := &dns.Client{Timeout: 3 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, addr)
		return r, err
	}
	return s
}

func enrolled(cfg *config.Config, ip string) bool {
	// Unlike the other listeners, DNS never serves unenrolled clients: answering arbitrary
	// clients would redirect devices the user has not confirmed they own.
	for _, e := range cfg.Enrolled {
		if e.IP == ip {
			return true
		}
	}
	return false
}

// Answer builds the reply to a query from a client address.
func (s *Server) Answer(ctx context.Context, clientIP string, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	if !enrolled(s.cfg, clientIP) || len(r.Question) == 0 {
		m.Rcode = dns.RcodeRefused
		return m
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	if s.names[name] {
		m.Authoritative = true
		if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY) && s.answer.To4() != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: s.answer.To4(),
			})
		}
		// AAAA and other types get an empty answer so the device falls back to IPv4.
		s.log.Debug("answered", "client", clientIP, "name", name)
		return m
	}
	resp, err := s.exchange(ctx, r, s.upstream)
	if err != nil || resp == nil {
		m.Rcode = dns.RcodeServerFailure
		return m
	}
	return resp
}

// Run serves UDP and TCP until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
		_ = w.WriteMsg(s.Answer(ctx, host, r))
	})
	servers := []*dns.Server{
		{Addr: s.cfg.DNS.Listen, Net: "udp", Handler: handler},
		{Addr: s.cfg.DNS.Listen, Net: "tcp", Handler: handler},
	}
	errs := make(chan error, len(servers))
	for _, srv := range servers {
		go func() { errs <- srv.ListenAndServe() }()
	}
	s.log.Info("listening", "addr", s.cfg.DNS.Listen, "answer", s.cfg.DNS.AnswerIP, "names", len(s.names))
	select {
	case <-ctx.Done():
	case err := <-errs:
		return err
	}
	for _, srv := range servers {
		_ = srv.Shutdown()
	}
	return nil
}
