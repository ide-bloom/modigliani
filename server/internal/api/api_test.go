package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/logging"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func call(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPI(t *testing.T) {
	eng := testutil.Engine(t)
	p := eng.Profiles()[0]
	eng.Touch(context.Background(), p, "SN-1", "10.0.0.2", map[string]string{"serial": "SN-1"})
	eng.ApplyExtracts(context.Background(), p, "SN-1", p.Handlers.HTTP[2].Extract, map[string]any{"body": map[string]any{"on": "ON", "w": 4.0}})
	srv := httptest.NewServer(New(eng, "s3cret", testutil.Logger(), logging.NewRing(10), "test").Handler())
	defer srv.Close()

	if code, _ := call(t, srv, "GET", "/api/health", "", ""); code != 200 {
		t.Errorf("health %d", code)
	}
	if code, _ := call(t, srv, "GET", "/", "", ""); code != 200 {
		t.Errorf("status page %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/devices", "", ""); code != 401 {
		t.Errorf("no token %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/devices", "nope", ""); code != 401 {
		t.Errorf("wrong token %d", code)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/devices", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var devs []engine.DeviceView
	_ = json.NewDecoder(resp.Body).Decode(&devs)
	_ = resp.Body.Close()
	if len(devs) != 1 || devs[0].ID != "lab/SN-1" || devs[0].State["power"] != true || !devs[0].Online || len(devs[0].Entities) == 0 {
		t.Fatalf("devices %+v", devs)
	}
	if code, _ := call(t, srv, "POST", "/api/devices/lab/SN-1/commands", "s3cret", `{"variable":"power","value":"off"}`); code != 202 {
		t.Errorf("command %d", code)
	}
	if code, _ := call(t, srv, "POST", "/api/devices/lab/SN-1/commands", "s3cret", `{"variable":"setpoint","value":99}`); code != 400 {
		t.Errorf("out of range %d", code)
	}
	if code, _ := call(t, srv, "POST", "/api/devices/lab/nope/commands", "s3cret", `{"variable":"power","value":true}`); code != 404 {
		t.Errorf("unknown device %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/unhandled", "s3cret", ""); code != 200 {
		t.Errorf("unhandled %d", code)
	}
	if code, _ := call(t, srv, "GET", "/api/profiles", "s3cret", ""); code != 200 {
		t.Errorf("profiles %d", code)
	}
}

func TestEventsWebSocket(t *testing.T) {
	eng := testutil.Engine(t)
	srv := httptest.NewServer(New(eng, "tok", testutil.Logger(), logging.NewRing(10), "test").Handler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/events?token=tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	time.Sleep(100 * time.Millisecond)
	eng.Touch(ctx, eng.Profiles()[0], "NEW", "10.0.0.3", nil)
	_, data, err := conn.Read(ctx)
	if err != nil || !strings.Contains(string(data), `"type":"device"`) {
		t.Fatalf("event %s %v", data, err)
	}
}
