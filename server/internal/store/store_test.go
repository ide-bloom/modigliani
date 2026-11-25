package store

import (
	"context"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDevicesAndState(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0)
	isNew, err := s.Touch(ctx, "p", "k", "10.0.0.2", map[string]string{"a": "1"}, now)
	if err != nil || !isNew {
		t.Fatalf("touch %v %v", isNew, err)
	}
	if isNew, _ = s.Touch(ctx, "p", "k", "10.0.0.2", map[string]string{"b": "2"}, now.Add(time.Second)); isNew {
		t.Error("second touch is not new")
	}
	d, ok, _ := s.Device(ctx, "p", "k")
	if !ok || d.Vars["a"] != "1" || d.Vars["b"] != "2" || !d.LastSeen.Equal(now.Add(time.Second)) {
		t.Errorf("device %+v", d)
	}
	if err := s.SetDesired(ctx, "p", "k", "power", true, now); err != nil {
		t.Fatal(err)
	}
	changed, _ := s.SetReported(ctx, "p", "k", "power", false, now)
	st, _ := s.State(ctx, "p", "k")
	if !changed || st["power"].Desired != true || st["power"].Reported != false {
		t.Errorf("state %+v", st)
	}
	// Reaching the desired value clears it: the command has been carried out.
	_, _ = s.SetReported(ctx, "p", "k", "power", true, now)
	st, _ = s.State(ctx, "p", "k")
	if st["power"].Desired != nil || st["power"].Reported != true {
		t.Errorf("desired not cleared %+v", st)
	}
	if changed, _ := s.SetReported(ctx, "p", "k", "power", true, now); changed {
		t.Error("same value is not a change")
	}
}

func TestCommandsTokensCounters(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Unix(1_800_000_000, 0)
	id, _ := s.Enqueue(ctx, "p", "k", "set_power", "power", true, "queued", now)
	_, _ = s.Enqueue(ctx, "p", "k", "set_other", "x", 1, "queued", now)
	cmds, err := s.TakeQueued(ctx, "p", "k", []string{"set_power"}, now)
	if err != nil || len(cmds) != 1 || cmds[0].ID != id || cmds[0].Value != true {
		t.Fatalf("take %v %v", cmds, err)
	}
	if again, _ := s.TakeQueued(ctx, "p", "k", []string{"set_power"}, now); len(again) != 0 {
		t.Error("delivered commands are not delivered twice")
	}
	_ = s.IssueToken(ctx, "tok", "p", "k", now.Add(time.Hour))
	if key, valid, _ := s.TokenDevice(ctx, "tok", "p", now); key != "k" || !valid {
		t.Error("token valid")
	}
	if _, valid, _ := s.TokenDevice(ctx, "tok", "p", now.Add(2*time.Hour)); valid {
		t.Error("token expired")
	}
	if _, valid, _ := s.TokenDevice(ctx, "tok", "other", now); valid {
		t.Error("tokens are per profile")
	}
	a, _ := s.NextSeq(ctx, "p", "k", "seq")
	b, _ := s.NextSeq(ctx, "p", "k", "seq")
	if a != 1 || b != 2 {
		t.Errorf("seq %d %d", a, b)
	}
	_ = s.AddUnhandled(ctx, Unhandled{TS: now, Protocol: "http", Remote: "1.2.3.4", Summary: "GET /x", Detail: "{}"})
	if u, _ := s.ListUnhandled(ctx, 10); len(u) != 1 || u[0].Summary != "GET /x" {
		t.Errorf("unhandled %v", u)
	}
}

func TestPersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, _ := Open(ctx, dir)
	_, _ = s.Touch(ctx, "p", "k", "", nil, time.Now())
	_ = s.Close()
	s2, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if devs, _ := s2.Devices(ctx); len(devs) != 1 {
		t.Errorf("devices after restart: %v", devs)
	}
}
