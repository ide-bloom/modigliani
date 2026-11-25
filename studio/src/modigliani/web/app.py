"""The local Studio UI: annotation timeline, profile review and the scrub diff.

It binds to 127.0.0.1 only and is started by `modigliani annotate` and `modigliani review`.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from modigliani.annotate.model import AnnotationSet
from modigliani.capture.model import Capture
from modigliani.infer.sessions import build_sessions
from modigliani.profile.io import dump_profile
from modigliani.profile.scrub import scrub
from modigliani.profile.validate import validate


@dataclass
class StudioState:
    capture_path: Path | None = None
    annotations_path: Path | None = None
    profile_path: Path | None = None


class AnnotationIn(BaseModel):
    label: str
    ts: float | None = None
    device: str | None = None


class ProfileIn(BaseModel):
    text: str


def _timeline(capture: Capture) -> list[dict[str, Any]]:
    sess = build_sessions([capture])
    events: list[dict[str, Any]] = []
    for ex in sess.http:
        status = ex.resp.status if ex.resp else "-"
        events.append(
            {
                "ts": ex.ts,
                "dir": "up",
                "protocol": "http",
                "flow": ex.ref.flow,
                "message": ex.ref.message,
                "summary": f"{ex.req.method} {ex.host}{ex.req.path} -> {status}",
            }
        )
    for s in sess.mqtt:
        for e in s.events:
            if e.packet.type in ("PUBLISH", "CONNECT", "SUBSCRIBE"):
                what = e.packet.topic or e.packet.client_id or ",".join(t for t, _ in e.packet.subscriptions)
                events.append(
                    {
                        "ts": e.ts,
                        "dir": e.dir.value,
                        "protocol": "mqtt",
                        "flow": e.ref.flow,
                        "message": e.ref.message,
                        "summary": f"{e.packet.type} {what} {e.packet.payload[:80]!r}",
                    }
                )
    for c in sess.coap:
        events.append(
            {
                "ts": c.ts,
                "dir": c.dir.value,
                "protocol": "coap",
                "flow": c.ref.flow,
                "message": c.ref.message,
                "summary": f"{c.msg.mtype} {c.msg.method if c.msg.is_request else c.msg.code_str} {c.msg.path} {c.msg.payload.hex()}",
            }
        )
    for w in sess.ws:
        events.append(
            {
                "ts": w.ts,
                "dir": w.dir.value,
                "protocol": "websocket",
                "flow": w.ref.flow,
                "message": w.ref.message,
                "summary": w.msg.payload[:120].decode(errors="replace"),
            }
        )
    for t in sess.tls:
        events.append(
            {
                "ts": t.start,
                "dir": "up",
                "protocol": "tls",
                "flow": t.flow,
                "message": 0,
                "summary": f"{t.host}:{t.port} {t.outcome.value} ({t.bytes_up}/{t.bytes_down} bytes)",
            }
        )
    return sorted(events, key=lambda e: e["ts"])


def create_app(state: StudioState) -> FastAPI:
    app = FastAPI(title="Modigliani Studio", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return resources.files("modigliani.web").joinpath("static/index.html").read_text(encoding="utf-8")

    @app.get("/api/state")
    def get_state() -> dict[str, Any]:
        return {
            "capture": state.capture_path.name if state.capture_path else None,
            "profile": state.profile_path.name if state.profile_path else None,
            "now": time.time(),
        }

    @app.get("/api/timeline")
    def timeline() -> list[dict[str, Any]]:
        if state.capture_path is None or not state.capture_path.exists():
            return []
        return _timeline(Capture.load(state.capture_path))

    def _annotations() -> AnnotationSet:
        if state.annotations_path is None:
            raise HTTPException(404, "no capture selected")
        return AnnotationSet.load(state.annotations_path, state.capture_path.name if state.capture_path else "")

    @app.get("/api/annotations")
    def list_annotations() -> list[dict[str, Any]]:
        return [a.model_dump(mode="json") for a in _annotations().annotations]

    @app.post("/api/annotations")
    def add_annotation(body: AnnotationIn) -> dict[str, Any]:
        if state.annotations_path is None:
            raise HTTPException(404, "no capture selected")
        capture = state.capture_path.name if state.capture_path else ""
        return AnnotationSet.append(state.annotations_path, body.label, body.ts, capture, body.device).model_dump(
            mode="json"
        )

    @app.delete("/api/annotations/{index}")
    def delete_annotation(index: int) -> dict[str, int]:
        anns = _annotations()
        if not 0 <= index < len(anns.annotations):
            raise HTTPException(404, "no such annotation")
        anns.annotations.pop(index)
        assert state.annotations_path is not None
        anns.save(state.annotations_path)
        return {"remaining": len(anns.annotations)}

    def _profile_path() -> Path:
        if state.profile_path is None or not state.profile_path.exists():
            raise HTTPException(404, "no profile selected")
        return state.profile_path

    @app.get("/api/profile")
    def get_profile() -> dict[str, Any]:
        path = _profile_path()
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
        _, errors = validate(data)
        return {"name": path.name, "text": text, "errors": errors}

    @app.put("/api/profile")
    def put_profile(body: ProfileIn) -> dict[str, Any]:
        path = _profile_path()
        try:
            data = json.loads(body.text) if path.suffix == ".json" else yaml.safe_load(body.text)
        except (ValueError, yaml.YAMLError) as exc:
            return {"saved": False, "errors": [f"parse error: {exc}"]}
        if not isinstance(data, dict):
            return {"saved": False, "errors": ["a profile must be a mapping"]}
        profile, errors = validate(data)
        if profile is None or errors:
            return {"saved": False, "errors": errors}
        path.write_text(body.text, encoding="utf-8")
        return {"saved": True, "errors": []}

    @app.get("/api/profile/scrub")
    def scrub_preview() -> dict[str, Any]:
        path = _profile_path()
        _, errors = validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        from modigliani.profile.io import load_profile

        scrubbed, changes = scrub(load_profile(path))
        return {
            "changes": [c.__dict__ for c in changes],
            "result": dump_profile(scrubbed),
            "errors": errors,
        }

    return app
