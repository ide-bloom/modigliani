package rawserver

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func TestProcessAndTCP(t *testing.T) {
	eng := testutil.Engine(t)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	cfg := &config.Config{Raw: config.Raw{Listen: map[string]string{"tcp/9000": addr}}}
	s := New(eng, cfg, testutil.Logger())
	p := eng.Profiles()[0]
	reply, key := s.Process(context.Background(), "10.0.0.8", p, &p.Handlers.Raw[0], testutil.UpFrame(20, 0, 9))
	if key != "10.0.0.8" || len(reply) != 4 {
		t.Fatalf("reply %x key %q", reply, key)
	}
	if reply, _ := s.Process(context.Background(), "10.0.0.8", p, &p.Handlers.Raw[0], []byte{1, 2, 3}); reply != nil {
		t.Error("unknown frames get no reply")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Run(ctx) }()
	var conn net.Conn
	var err error
	for range 50 {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Two frames in one write, the second split across writes: framing must reassemble.
	a, b := testutil.UpFrame(20, 0, 4), testutil.UpFrame(20, 0, 5)
	_, _ = conn.Write(append(a, b[:2]...))
	_, _ = conn.Write(b[2:])
	buf := make([]byte, 8)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("expected two replies: %v", err)
	}
	st, _ := eng.Store().State(ctx, "lab", "127.0.0.1")
	if st["level"].Reported != 5.0 {
		t.Errorf("state %+v", st)
	}
}
