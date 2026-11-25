"""A throwaway "vendor" PKI for the cloud simulators (generated per test run, never committed)."""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class ServerCert:
    cert: Path
    key: Path


@dataclass(frozen=True)
class VendorPki:
    ca_cert: Path
    ca_key: ec.EllipticCurvePrivateKey
    ca: x509.Certificate
    directory: Path

    def issue(self, name: str, hostnames: list[str]) -> ServerCert:
        key = ec.generate_private_key(ec.SECP256R1())
        sans: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
            .issuer_name(self.ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        cert_path = self.directory / f"{name}.crt"
        key_path = self.directory / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        return ServerCert(cert_path, key_path)


def make_vendor_pki(directory: Path) -> VendorPki:
    directory.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example Vendor Root CA (test)")])
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(hours=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    path = directory / "vendor-ca.crt"
    path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return VendorPki(path, key, ca, directory)
