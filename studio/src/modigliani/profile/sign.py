"""Detached ed25519 signatures over the exact bytes of a profile file.

Signing raw bytes (instead of a canonical JSON form) means Python and Go agree trivially:
`<profile>.sig` holds the public key, a key id and the signature.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel

from modigliani.workspace import user_config_dir, write_private


class SignatureFile(BaseModel):
    algorithm: str = "ed25519"
    key_id: str
    public_key: str
    signature: str


@dataclass(frozen=True)
class Verification:
    status: str  # valid | invalid | unsigned | untrusted
    key_id: str | None = None


def default_key_path() -> Path:
    return user_config_dir() / "signing" / "ed25519.pem"


def key_id(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def public_raw(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def generate_key(path: Path | None = None, *, force: bool = False) -> Path:
    path = path or default_key_path()
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists; pass --force to replace it")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    write_private(path, pem)
    return path


def load_key(path: Path | None = None) -> Ed25519PrivateKey:
    path = path or default_key_path()
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an ed25519 key")
    return key


def sig_path(profile_path: Path) -> Path:
    return profile_path.with_name(profile_path.name + ".sig")


def sign_file(profile_path: Path, key: Ed25519PrivateKey) -> Path:
    data = profile_path.read_bytes()
    raw = public_raw(key)
    sig = SignatureFile(
        key_id=key_id(raw),
        public_key=base64.b64encode(raw).decode(),
        signature=base64.b64encode(key.sign(data)).decode(),
    )
    out = sig_path(profile_path)
    out.write_text(sig.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return out


def verify_file(profile_path: Path, trusted: list[str] | None = None) -> Verification:
    """Verify a profile. `trusted` lists base64 public keys; None means any valid key is accepted."""
    sp = sig_path(profile_path)
    if not sp.exists():
        return Verification("unsigned")
    try:
        sig = SignatureFile.model_validate(json.loads(sp.read_text(encoding="utf-8")))
        raw = base64.b64decode(sig.public_key)
        Ed25519PublicKey.from_public_bytes(raw).verify(base64.b64decode(sig.signature), profile_path.read_bytes())
    except (InvalidSignature, ValueError):
        return Verification("invalid")
    if trusted is not None and sig.public_key not in trusted:
        return Verification("untrusted", sig.key_id)
    return Verification("valid", sig.key_id)
