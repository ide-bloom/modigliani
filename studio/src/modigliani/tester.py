"""`modigliani test`: replay the device's side of recorded sessions against Modigliani Server.

The real server binary runs on loopback with plaintext listeners. Each recorded device
message is sent again and the server's answer is compared with what the vendor answered:
same status/code, and the same JSON shape (keys and types) or a valid frame. Values such as
tokens and timestamps legitimately differ; tokens the server issues are substituted into
later requests just as the device would.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from modigliani.capture.model import Capture, Direction
from modigliani.infer import decoders as d
from modigliani.infer import frames as fr
from modigliani.infer.sessions import build_sessions
from modigliani.infer.values import flatten, parse_body
from modigliani.profile.model import Profile


@dataclass
class ReplayResult:
    protocol: str
    what: str
    ok: bool
    detail: str = ""


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


@dataclass
class ServerHandle:
    process: subprocess.Popen[bytes]
    http_port: int
    mqtt_port: int
    coap_port: int
    api_port: int
    token: str
    workdir: Path
    raw_ports: dict[str, int]

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()


def find_server_binary(explicit: Path | None = None) -> Path:
    candidates = [explicit] if explicit else []
    env = os.environ.get("MODIGLIANI_SERVER_BIN")
    if env:
        candidates.append(Path(env))
    exe = "modigliani-server.exe" if os.name == "nt" else "modigliani-server"
    which = shutil.which(exe)
    if which:
        candidates.append(Path(which))
    for c in candidates:
        if c and c.exists():
            return c
    raise FileNotFoundError(
        "modigliani-server not found: build it (`go build ./server/cmd/modigliani-server`), put it on PATH "
        "or pass --server-bin / MODIGLIANI_SERVER_BIN"
    )


@contextlib.contextmanager
def running_server(binary: Path, profile_path: Path, profile: Profile) -> Iterator[ServerHandle]:
    work = Path(tempfile.mkdtemp(prefix="modigliani-test-"))
    try:
        (work / "profiles").mkdir()
        shutil.copy(profile_path, work / "profiles" / profile_path.name)
        token = secrets.token_hex(16)
        ports = {"http": free_port(), "mqtt": free_port(), "coap": free_port(socket.SOCK_DGRAM), "api": free_port()}
        raw_ports = {
            f"{h.transport}/{h.port}": free_port(socket.SOCK_DGRAM if h.transport == "udp" else socket.SOCK_STREAM)
            for h in profile.handlers.raw
        }
        config = {
            "data_dir": str(work / "data"),
            "api": {"listen": f"127.0.0.1:{ports['api']}", "token": token},
            "http": {"listen": [f"127.0.0.1:{ports['http']}"]},
            "mqtt": {"listen": [f"127.0.0.1:{ports['mqtt']}"]},
            "coap": {"listen": [f"127.0.0.1:{ports['coap']}"]},
            "raw": {"listen": {k: f"127.0.0.1:{v}" for k, v in raw_ports.items()}},
            "log_level": "warn",
        }
        (work / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
        proc = subprocess.Popen(
            [str(binary), "--profiles", str(work / "profiles"), "--config", str(work / "config.yaml")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        handle = ServerHandle(proc, ports["http"], ports["mqtt"], ports["coap"], ports["api"], token, work, raw_ports)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                raise RuntimeError(f"modigliani-server exited: {err}")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", ports["api"], timeout=1)
                conn.request("GET", "/api/health")
                if conn.getresponse().status == 200:
                    break
            except OSError:
                time.sleep(0.2)
        try:
            yield handle
        finally:
            handle.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shape(value[0])] if value else []
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int | float):
        return "number"
    if value is None:
        return "null"
    return "string"


def _shape_ok(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _shape_ok(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list)
    return bool(expected == actual or expected == "null" or actual == "null")


def replay(
    profile: Profile, captures: list[Capture], server: ServerHandle, device: str | None = None
) -> list[ReplayResult]:
    sess = build_sessions(captures, device)
    results: list[ReplayResult] = []
    results += _replay_http(sess.http, server)
    results += _replay_mqtt(profile, sess.mqtt, server)
    results += _replay_coap(profile, sess.coap, server)
    results += _replay_raw(profile, sess.raw, server)
    return results


def _replay_http(exchanges: list[Any], server: ServerHandle) -> list[ReplayResult]:
    out: list[ReplayResult] = []
    tokens: dict[str, str] = {}
    for ex in sorted(exchanges, key=lambda e: e.ts):
        target, body = ex.req.target, ex.req.body
        headers = {
            k: v for k, v in ex.req.headers if k.lower() not in ("content-length", "transfer-encoding", "connection")
        }
        for old, new in tokens.items():
            target = target.replace(old, new)
            body = body.replace(old.encode(), new.encode())
            headers = {k: v.replace(old, new) for k, v in headers.items()}
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.http_port, timeout=5)
            conn.request(ex.req.method, target, body=body or None, headers=headers)
            resp = conn.getresponse()
            rbody = resp.read()
        except OSError as exc:
            out.append(ReplayResult("http", f"{ex.req.method} {ex.req.path}", False, str(exc)))
            continue
        what = f"{ex.req.method} {ex.req.path}"
        if ex.resp is None:
            out.append(ReplayResult("http", what, resp.status < 500, f"status {resp.status}"))
            continue
        ok = resp.status == ex.resp.status
        detail = f"status {resp.status} (vendor {ex.resp.status})"
        expected = parse_body(ex.resp.header("content-type"), ex.resp.body)
        actual = parse_body(resp.getheader("content-type"), rbody)
        if expected is not None:
            if not _shape_ok(_shape(expected), _shape(actual)):
                ok, detail = (
                    False,
                    f"body shape differs: vendor {json.dumps(_shape(expected))} vs server {json.dumps(_shape(actual))}",
                )
            # Learn issued tokens: same path in both bodies, token-like vendor value.
            ev, av = flatten(expected), flatten(actual)
            for p, v in ev.items():
                if isinstance(v, str) and len(v) >= 16 and isinstance(av.get(p), str) and av[p] != v:
                    tokens[v] = str(av[p])
        out.append(ReplayResult("http", what, ok, detail))
    return out


def _replay_mqtt(profile: Profile, sessions: list[Any], server: ServerHandle) -> list[ReplayResult]:
    if not sessions:
        return []
    import paho.mqtt.client as mqtt
    from paho.mqtt.enums import CallbackAPIVersion

    out: list[ReplayResult] = []
    topics = profile.handlers.mqtt.topics if profile.handlers.mqtt else []
    by_id = {t.id: t for t in topics}
    reply_topics = [t.topic for t in topics if t.reply_to]
    request_topics = [by_id[t.reply_to].topic for t in topics if t.reply_to and t.reply_to in by_id]
    for s in sessions:
        if s.connect is None:
            continue
        probe = _MqttProbe()
        received, connected, rc_holder = probe.received, probe.connected, probe.rc
        client = mqtt.Client(
            CallbackAPIVersion.VERSION2,
            client_id=s.connect.client_id,
            protocol=mqtt.MQTTv5 if s.level == 5 else mqtt.MQTTv311,
        )
        if s.connect.username is not None:
            client.username_pw_set(s.connect.username, (s.connect.password or b"").decode(errors="replace"))

        client.on_connect = probe.on_connect
        client.on_message = probe.on_message
        try:
            client.connect("127.0.0.1", server.mqtt_port, keepalive=s.connect.keepalive or 30)
        except OSError as exc:
            out.append(ReplayResult("mqtt", "CONNECT", False, str(exc)))
            continue
        client.loop_start()
        ok = connected.wait(5) and bool(rc_holder) and not getattr(rc_holder[0], "is_failure", False)
        out.append(
            ReplayResult(
                "mqtt", f"CONNECT {s.connect.client_id}", ok, f"reason {rc_holder[0] if rc_holder else 'timeout'}"
            )
        )
        for e in s.events:
            if e.dir is Direction.UP and e.packet.type == "SUBSCRIBE":
                for topic, qos in e.packet.subscriptions:
                    client.subscribe(topic, qos)
        time.sleep(0.3)
        expected_replies = 0
        for e in s.events:
            if e.dir is Direction.UP and e.packet.type == "PUBLISH":
                client.publish(e.packet.topic, e.packet.payload, qos=min(e.packet.qos, 1), retain=e.packet.retain)
                if any(_topic_matches(t, e.packet.topic) for t in request_topics):
                    expected_replies += 1
        time.sleep(1.0)
        client.loop_stop()
        client.disconnect()
        published = sum(1 for e in s.events if e.dir is Direction.UP and e.packet.type == "PUBLISH")
        out.append(ReplayResult("mqtt", f"{published} device publishes", True, "accepted"))
        if expected_replies:
            got = len([t for t in received if any(_topic_matches(r, t) for r in reply_topics)])
            out.append(
                ReplayResult(
                    "mqtt", "request/response topics", got >= expected_replies, f"{got}/{expected_replies} replies"
                )
            )
    return out


class _MqttProbe:
    def __init__(self) -> None:
        self.received: list[str] = []
        self.connected = threading.Event()
        self.rc: list[Any] = []

    def on_connect(self, c: Any, u: Any, f: Any, rc: Any, p: Any = None) -> None:
        self.rc.append(rc)
        self.connected.set()

    def on_message(self, c: Any, u: Any, msg: Any) -> None:
        self.received.append(msg.topic)


def _topic_matches(template: str, topic: str) -> bool:
    a, b = template.split("/"), topic.split("/")
    return len(a) == len(b) and all(x.startswith("{") or x == y for x, y in zip(a, b, strict=True))


def _replay_coap(profile: Profile, events: list[Any], server: ServerHandle) -> list[ReplayResult]:
    out: list[ReplayResult] = []
    reqs = [e for e in events if e.dir is Direction.UP and e.msg.is_request]
    downs = [e for e in events if e.dir is Direction.DOWN]
    frames = {f.id: f for f in profile.frames}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        for i, r in enumerate(reqs):
            expected = next((x for x in downs if x.msg.token == r.msg.token and x.ts >= r.ts - 0.01), None)
            msg = d.CoapMessage(r.msg.mtype, r.msg.code, (i + 1) & 0xFFFF, r.msg.token, r.msg.options, r.msg.payload)
            sock.sendto(d.encode_coap(msg), ("127.0.0.1", server.coap_port))
            try:
                data, _ = sock.recvfrom(2048)
                resp = d.decode_coap(data)
            except (OSError, d.DecodeError) as exc:
                out.append(ReplayResult("coap", f"{r.msg.method} {r.msg.path}", False, str(exc)))
                continue
            ok = expected is None or resp.code_str == expected.msg.code_str
            detail = f"code {resp.code_str}" + (f" (vendor {expected.msg.code_str})" if expected else "")
            if ok and expected is not None and expected.msg.payload:
                handler = next((h for h in profile.handlers.coap if h.response.frame), None)
                layout = frames.get(handler.response.frame.frame) if handler and handler.response.frame else None
                if layout is not None and layout.length == len(expected.msg.payload):
                    ok = len(resp.payload) == len(expected.msg.payload) and (
                        layout.checksum is None or fr.verify_checksum(resp.payload, layout.checksum)
                    )
                    detail += f", frame {resp.payload.hex()} ({'checksum ok' if ok else 'invalid frame'})"
            out.append(ReplayResult("coap", f"{r.msg.method} {r.msg.path}", ok, detail))
    return out


def _replay_raw(profile: Profile, streams: list[Any], server: ServerHandle) -> list[ReplayResult]:
    out: list[ReplayResult] = []
    for s in streams:
        port = server.raw_ports.get(f"{s.transport}/{s.port}")
        if port is None:
            continue
        ups = [c for c in s.chunks if c[1] is Direction.UP]
        try:
            if s.transport == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(2)
                    for _, _, data in ups:
                        sock.sendto(data, ("127.0.0.1", port))
                        with contextlib.suppress(OSError):
                            sock.recvfrom(4096)
            else:
                with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                    for _, _, data in ups:
                        sock.sendall(data)
                    sock.settimeout(1)
                    with contextlib.suppress(OSError):
                        sock.recv(4096)
            out.append(ReplayResult("raw", f"{s.transport}/{s.port}", True, f"{len(ups)} messages sent"))
        except OSError as exc:
            out.append(ReplayResult("raw", f"{s.transport}/{s.port}", False, str(exc)))
    return out
