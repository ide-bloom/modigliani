package dnsserver

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestAnswers(t *testing.T) {
	cfg := &config.Config{DNS: &config.DNS{AnswerIP: "192.168.1.50", Upstream: "192.0.2.53:53"},
		Enrolled: []config.Enrolled{{Name: "plug", IP: "192.168.1.20"}}}
	s := New(cfg, testutil.Logger(), []string{"api.vendor.example"})
	forwarded := 0
	s.exchange = func(_ context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
		forwarded++
		if addr != "192.0.2.53:53" {
			return nil, errors.New("wrong upstream")
		}
		r := new(dns.Msg)
		r.SetReply(m)
		return r, nil
	}
	ctx := context.Background()
	r := s.Answer(ctx, "192.168.1.20", query("API.vendor.example", dns.TypeA))
	if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.50" || !r.Authoritative {
		t.Fatalf("served name: %v", r)
	}
	if r := s.Answer(ctx, "192.168.1.20", query("api.vendor.example", dns.TypeAAAA)); len(r.Answer) != 0 || r.Rcode != dns.RcodeSuccess {
		t.Errorf("AAAA should be empty NOERROR: %v", r)
	}
	if r := s.Answer(ctx, "192.168.1.20", query("example.org", dns.TypeA)); forwarded != 1 || r.Rcode != dns.RcodeSuccess {
		t.Errorf("other names are forwarded: %v", r)
	}
	if r := s.Answer(ctx, "192.168.1.99", query("api.vendor.example", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Errorf("unenrolled clients are refused: %v", r)
	}
	empty := New(&config.Config{DNS: &config.DNS{AnswerIP: "192.168.1.50"}}, testutil.Logger(), nil)
	if r := empty.Answer(ctx, "192.168.1.20", query("x", dns.TypeA)); r.Rcode != dns.RcodeRefused {
		t.Error("with no enrolled devices DNS answers nobody")
	}
}
