"""The local certificate authority.

Its certificate is offered only to enrolled devices (in proxy mode and by the server).
It is never installed into the PC's trust store. The private key is encrypted with DPAPI
on Windows and stored with owner-only permissions elsewhere.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from modigliani import dpapi
from modigliani.workspace import write_private

CERT_FILE = "ca.crt"
KEY_FILE_PLAIN = "ca.key"
KEY_FILE_DPAPI = "ca.key.dpapi"
# RSA rather than ECDSA because many embedded TLS stacks in older devices only do RSA.
KEY_BITS = 2048


class CaError(RuntimeError):
    pass


@dataclass(frozen=True)
class CaInfo:
    subject: str
    fingerprint_sha256: str
    not_before: dt.datetime
    not_after: dt.datetime
    key_protection: str
    cert_path: Path


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def exists(ca_dir: Path) -> bool:
    return (ca_dir / CERT_FILE).exists() and ((ca_dir / KEY_FILE_DPAPI).exists() or (ca_dir / KEY_FILE_PLAIN).exists())


def init(ca_dir: Path, *, force: bool = False, use_dpapi: bool | None = None) -> CaInfo:
    if exists(ca_dir) and not force:
        raise CaError(f"a CA already exists in {ca_dir}; pass --force to replace it")
    if use_dpapi is None:
        use_dpapi = sys.platform == "win32"
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"Modigliani Local CA ({socket.gethostname()})"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Modigliani (local only)"),
        ]
    )
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    ca_dir.mkdir(parents=True, exist_ok=True)
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    for stale in (KEY_FILE_PLAIN, KEY_FILE_DPAPI):
        (ca_dir / stale).unlink(missing_ok=True)
    if use_dpapi:
        write_private(ca_dir / KEY_FILE_DPAPI, dpapi.protect(der))
    else:
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        write_private(ca_dir / KEY_FILE_PLAIN, pem)
    (ca_dir / CERT_FILE).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return info(ca_dir)


def load_cert(ca_dir: Path) -> x509.Certificate:
    path = ca_dir / CERT_FILE
    if not path.exists():
        raise CaError(f"no CA found in {ca_dir}; run `modigliani ca init`")
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_key(ca_dir: Path) -> rsa.RSAPrivateKey:
    if (ca_dir / KEY_FILE_DPAPI).exists():
        der = dpapi.unprotect((ca_dir / KEY_FILE_DPAPI).read_bytes())
        key = serialization.load_der_private_key(der, password=None)
    elif (ca_dir / KEY_FILE_PLAIN).exists():
        key = serialization.load_pem_private_key((ca_dir / KEY_FILE_PLAIN).read_bytes(), password=None)
    else:
        raise CaError(f"no CA key found in {ca_dir}; run `modigliani ca init`")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CaError("unexpected CA key type")
    return key


def info(ca_dir: Path) -> CaInfo:
    cert = load_cert(ca_dir)
    protection = "dpapi" if (ca_dir / KEY_FILE_DPAPI).exists() else "file (owner-only)"
    return CaInfo(
        subject=cert.subject.rfc4514_string(),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(":").upper(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_protection=protection,
        cert_path=ca_dir / CERT_FILE,
    )


def issue_leaf(ca_dir: Path, hostnames: list[str], days: int = 397) -> tuple[bytes, bytes]:
    """Issue a server certificate for the given names. Returns (cert PEM, key PEM)."""
    ca_cert = load_cert(ca_dir)
    ca_key = load_key(ca_dir)
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
    sans: list[x509.GeneralName] = []
    for h in hostnames:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            sans.append(x509.DNSName(h))
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def write_mitmproxy_confdir(ca_dir: Path, confdir: Path) -> None:
    """Materialise the CA in mitmproxy's expected layout inside a private temporary directory.

    mitmproxy only reads its CA from files, so the decrypted key exists on disk for the
    lifetime of a proxy session, owner-only, and the caller deletes the directory afterwards.
    """
    cert = load_cert(ca_dir)
    key = load_key(ca_dir)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    write_private(confdir / "mitmproxy-ca.pem", key_pem + cert_pem)
    (confdir / "mitmproxy-ca-cert.pem").write_bytes(cert_pem)
