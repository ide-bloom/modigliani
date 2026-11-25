package httpserver

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

	"github.com/ide-bloom/modigliani/server/internal/config"
	"github.com/ide-bloom/modigliani/server/internal/testutil"
)

func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	req.Host = "api.lab.example"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestLoginPollReportAndCommands(t *testing.T) {
	eng := testutil.Engine(t)
	srv := httptest.NewServer(New(eng, &config.Config{}, testutil.Logger()))
	defer srv.Close()

	status, login := do(t, srv, "POST", "/v1/login", "", map[string]any{"serial": "SN-1", "secret": "whatever"})
	token, _ := login["token"].(string)
	if status != 200 || len(token) != 32 || login["ttl"] != 3600.0 {
		t.Fatalf("login %d %v", status, login)
	}
	if status, _ := do(t, srv, "GET", "/v1/dev/SN-1/poll", "wrong", nil); status != 401 {
		t.Errorf("bad token: %d", status)
	}
	status, rep := do(t, srv, "POST", "/v1/dev/SN-1/report", token, map[string]any{"on": "ON", "w": 12.5})
	if status != 200 || rep["echo"] != "SN-1" || rep["ok"] != true {
		t.Fatalf("report %d %v", status, rep)
	}
	if at, _ := rep["at"].(float64); time.Since(time.Unix(int64(at), 0)) > time.Minute {
		t.Errorf("now.unix = %v", rep["at"])
	}
	st, _ := eng.Store().State(context.Background(), "lab", "SN-1")
	if st["power"].Reported != true || st["watts"].Reported != 12.5 {
		t.Errorf("state %+v", st)
	}
	_, poll := do(t, srv, "GET", "/v1/dev/SN-1/poll", token, nil)
	if q := poll["queue"].([]any); len(q) != 0 {
		t.Errorf("idle poll %v", poll)
	}
	if _, err := eng.SendCommand(context.Background(), "lab", "SN-1", "power", "", false); err != nil {
		t.Fatal(err)
	}
	_, poll = do(t, srv, "GET", "/v1/dev/SN-1/poll", token, nil)
	q := poll["queue"].([]any)
	if len(q) != 1 || q[0].(map[string]any)["on"] != "OFF" || q[0].(map[string]any)["seq"] != 1.0 {
		t.Fatalf("command delivery %v", poll)
	}
	if _, poll = do(t, srv, "GET", "/v1/dev/SN-1/poll", token, nil); len(poll["queue"].([]any)) != 0 {
		t.Error("commands are delivered once")
	}
}

func TestHousekeepingAndUnhandled(t *testing.T) {
	eng := testutil.Engine(t)
	srv := httptest.NewServer(New(eng, &config.Config{}, testutil.Logger()))
	defer srv.Close()
	if status, body := do(t, srv, "GET", "/v1/time", "", nil); status != 200 || body["epoch"] == nil {
		t.Errorf("time %d %v", status, body)
	}
	if devs, _ := eng.Store().Devices(context.Background()); len(devs) != 0 {
		t.Errorf("anonymous housekeeping must not create devices: %v", devs)
	}
	if status, _ := do(t, srv, "GET", "/v2/unknown", "", nil); status != 200 {
		t.Errorf("unhandled requests get the default response, got %d", status)
	}
	u, _ := eng.Store().ListUnhandled(context.Background(), 10)
	if len(u) != 1 || !strings.Contains(u[0].Summary, "/v2/unknown") {
		t.Errorf("unhandled %v", u)
	}
}

func TestEnrollmentIsEnforced(t *testing.T) {
	eng := testutil.Engine(t)
	cfg := &config.Config{Enrolled: []config.Enrolled{{Name: "x", IP: "10.9.9.9"}}}
	srv := httptest.NewServer(New(eng, cfg, testutil.Logger()))
	defer srv.Close()
	if status, _ := do(t, srv, "GET", "/v1/time", "", nil); status != http.StatusForbidden {
		t.Errorf("unenrolled client got %d", status)
	}
}

func TestWebSocketHandler(t *testing.T) {
	eng := testutil.Engine(t)
	srv := httptest.NewServer(New(eng, &config.Config{}, testutil.Logger()))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/SN-9", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"ping","id":7}`))
	_, data, err := conn.Read(ctx)
	if err != nil || string(data) != `{"id":7,"type":"pong"}` {
		t.Fatalf("reply %s %v", data, err)
	}
	_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"state","watts":3.5}`))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := eng.Store().State(ctx, "lab", "SN-9")
		if st["watts"].Reported == 3.5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("websocket extract did not update state")
}
