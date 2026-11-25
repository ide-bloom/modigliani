"""Workspace layout: where captures, the local CA and local profiles live.

The workspace defaults to the current directory so that the repository's .gitignore
(captures/, ca/, profiles/local/) protects user data when Studio runs from a checkout.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Workspace:
    root: Path

    @classmethod
    def from_env(cls, root: Path | None = None) -> Workspace:
        if root is None:
            env = os.environ.get("MODIGLIANI_HOME")
            root = Path(env) if env else Path.cwd()
        return cls(root.resolve())

    @property
    def captures(self) -> Path:
        return self.root / "captures"

    @property
    def ca_dir(self) -> Path:
        return self.root / "ca"

    @property
    def local_profiles(self) -> Path:
        return self.root / "profiles" / "local"

    @property
    def enrollment_file(self) -> Path:
        return self.root / "enrollment.json"

    def capture_path(self, name: str) -> Path:
        candidate = Path(name)
        if candidate.suffix or candidate.exists():
            return candidate
        return self.captures / f"{name}.mcap.json"

    @property
    def recording_marker(self) -> Path:
        """Names the capture being recorded right now, so `annotate` can attach to it."""
        return self.captures / ".recording"

    def current_capture(self) -> str | None:
        """The capture being recorded, else the most recently saved one."""
        if self.recording_marker.exists():
            name = self.recording_marker.read_text(encoding="utf-8").strip()
            if name:
                return name
        saved = sorted(self.captures.glob("*.mcap.json"), key=lambda p: p.stat().st_mtime)
        return saved[-1].name.removesuffix(".mcap.json") if saved else None

    def annotations_path(self, capture: Path) -> Path:
        base = capture.name.removesuffix(".gz").removesuffix(".json").removesuffix(".mcap")
        return capture.with_name(f"{base}.annotations.json")


def user_config_dir() -> Path:
    """Per-user configuration (signing keys live here, never inside a repository)."""
    override = os.environ.get("MODIGLIANI_CONFIG_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Modigliani"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "modigliani"


def write_private(path: Path, data: bytes) -> None:
    """Write a file readable only by its owner (best effort on Windows, where ACLs apply)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_BINARY matters on Windows: without it os.open translates newlines and corrupts keys.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if sys.platform != "win32":
        os.chmod(path, 0o600)
