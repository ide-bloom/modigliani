package coapserver

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/plgd-dev/go-coap/v3/message"
	"github.com/plgd-dev/go-coap/v3/message/codes"
	"github.com/plgd-dev/go-coap/v3/udp"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func TestFrameTelemetryAndCommand(t *testing.T) {
	eng := testutil.Engine(t)
	s := New(eng, &config.Config{}, testutil.Logger())
	ctx := context.Background()
	resp, ok := s.Handle(ctx, "10.0.0.4", "POST", "/d/S9/t", testutil.UpFrame(21.6, 0, 3))
	if !ok || resp.Code != codes.Changed {
		t.Fatalf("resp %+v", resp)
	}
	if !bytes.Equal(resp.Payload, []byte{0xA5, 1, 0, testutil.CRC8([]byte{1, 0})}) {
		t.Errorf("payload %x", resp.Payload)
	}
	st, _ := eng.Store().State(ctx, "lab", "S9")
	if st["temp"].Reported != 21.6 || st["led"].Reported != false {
		t.Errorf("state %+v", st)
	}
	if _, err := eng.SendCommand(ctx, "lab", "S9", "led", "", true); err != nil {
		t.Fatal(err)
	}
	resp, _ = s.Handle(ctx, "10.0.0.4", "POST", "/d/S9/t", testutil.UpFrame(21.7, 0, 3))
	if resp.Payload[2] != 1 {
		t.Errorf("desired led must be sent: %x", resp.Payload)
	}
	bad := testutil.UpFrame(21.7, 0, 3)
	bad[len(bad)-1] ^= 0xFF
	if resp, _ := s.Handle(ctx, "10.0.0.4", "POST", "/d/S9/t", bad); resp.Code != codes.BadRequest {
		t.Errorf("bad checksum: %v", resp.Code)
	}
	if resp, _ := s.Handle(ctx, "10.0.0.4", "GET", "/nope", nil); resp.Code != codes.NotFound {
		t.Errorf("unknown resource: %v", resp.Code)
	}
}

func TestOverUDP(t *testing.T) {
	eng := testutil.Engine(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = New(eng, &config.Config{}, testutil.Logger()).Run(ctx, []string{addr}) }()
	time.Sleep(200 * time.Millisecond)
	conn, err := udp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	resp, err := conn.Post(rctx, "/d/S1/t", message.AppOctets, bytes.NewReader(testutil.UpFrame(20, 1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := resp.ReadBody()
	if resp.Code() != codes.Changed || len(body) != 4 || body[2] != 1 {
		t.Errorf("code %v body %x", resp.Code(), body)
	}
}
