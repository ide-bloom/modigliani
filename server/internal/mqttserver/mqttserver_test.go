package mqttserver

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func TestDeviceSession(t *testing.T) {
	eng := testutil.Engine(t)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := New(eng, &config.Config{}, testutil.Logger())
	go func() { _ = srv.Run(ctx, []string{addr}, nil, nil) }()

	var mu sync.Mutex
	got := map[string][]byte{}
	opts := paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("lab-D7").SetUsername("D7").SetPassword("anything").
		SetConnectRetry(true).SetConnectRetryInterval(100 * time.Millisecond)
	client := paho.NewClient(opts)
	tok := client.Connect()
	if !tok.WaitTimeout(5*time.Second) || tok.Error() != nil {
		t.Fatalf("device credentials must be accepted: %v", tok.Error())
	}
	defer client.Disconnect(100)
	handler := func(_ paho.Client, m paho.Message) {
		mu.Lock()
		defer mu.Unlock()
		got[m.Topic()] = m.Payload()
	}
	client.Subscribe("lab/D7/#", 1, handler).WaitTimeout(2 * time.Second)

	client.Publish("lab/D7/tele", 0, false, `{"t": 19.5, "sp": 20}`).WaitTimeout(2 * time.Second)
	waitFor(t, func() bool {
		st, _ := eng.Store().State(ctx, "lab", "D7")
		return st["temp"].Reported == 19.5
	})
	client.Publish("lab/D7/time/get", 0, false, `{"n": 3}`).WaitTimeout(2 * time.Second)
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		var reply map[string]any
		return json.Unmarshal(got["lab/D7/time"], &reply) == nil && reply["ask"] == 3.0 && reply["now"] != nil
	})
	if _, err := eng.SendCommand(ctx, "lab", "D7", "setpoint", "", 22.5); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return string(got["lab/D7/cmd"]) == `{"setpoint":22.5}`
	})
}

func TestUnknownClientsAreRejected(t *testing.T) {
	eng := testutil.Engine(t)
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = New(eng, &config.Config{}, testutil.Logger()).Run(ctx, []string{addr}, nil, nil) }()
	time.Sleep(200 * time.Millisecond)
	client := paho.NewClient(paho.NewClientOptions().AddBroker("tcp://" + addr).SetClientID("stranger").SetUsername("x"))
	tok := client.Connect()
	tok.WaitTimeout(3 * time.Second)
	if tok.Error() == nil {
		t.Error("a client matching no profile must be refused")
	}
}
