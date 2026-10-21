import json
import socket
import ssl
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class RouterTransport(StrEnum):
    UNREACHABLE = "unreachable"   # no TCP connection, so nothing is decided
    NOT_TLS = "not-tls"           # no TLS handshake, so plaintext Zenoh or something else
    TLS = "tls"                   # TLS with no client certificate demanded
    MTLS = "mtls"                 # the router refused a client without a certificate


class RouterProbe(BaseModel):
    """What the router's port answered before any Zenoh session was attempted."""
    model_config = ConfigDict(frozen=True)

    transport: RouterTransport
    detail: str


def split_endpoint(endpoint: str) -> tuple[str, int]:
    """`host:port`, `[v6]:port` or a bare host, which means port 7447."""
    if endpoint.startswith("["):
        host, _, rest = endpoint[1:].partition("]")
        return host, int(rest.lstrip(":") or 7447)
    host, sep, port = endpoint.rpartition(":")
    return (host, int(port)) if sep else (endpoint, 7447)


def probe_router(
    host: str, port: int, timeout_s: float = 3.0, attempts: int = 5,
) -> RouterProbe:
    """Open TCP, then try TLS with no client certificate. Only a certificate alert means mTLS."""
    found = _attempt(host, port, timeout_s)
    # A close with no alert is ambiguous: the alert can be lost as the peer hangs up.
    for _ in range(attempts - 1):
        if not found.detail.endswith(CLOSED_WITHOUT_ALERT):
            break
        found = _attempt(host, port, timeout_s)
    return found


CLOSED_WITHOUT_ALERT = "closed the connection with no alert"


def _attempt(host: str, port: int, timeout_s: float) -> RouterProbe:
    try:
        raw = socket.create_connection((host, port), timeout=timeout_s)
    except OSError as exc:
        return RouterProbe(transport=RouterTransport.UNREACHABLE,
                           detail=f"TCP connect to {host}:{port} failed: {exc}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with raw:
        try:
            tls = context.wrap_socket(raw, server_hostname=host)
        except OSError as exc:
            return _handshake_failed(f"{host}:{port}", exc)
        with tls:
            return _after_handshake(tls, timeout_s)


def _handshake_failed(address: str, exc: OSError) -> RouterProbe:
    if isinstance(exc, ssl.SSLError) and "certificate" in str(exc).lower():
        return RouterProbe(transport=RouterTransport.MTLS,
                           detail=f"TLS handshake refused for want of a client certificate: {exc}")
    return RouterProbe(transport=RouterTransport.NOT_TLS,
                       detail=f"{address} did not complete a TLS handshake: {exc}")


def _after_handshake(tls: ssl.SSLSocket, timeout_s: float) -> RouterProbe:
    """TLS 1.3 sends the client-certificate verdict after the handshake, so read for it."""
    version = tls.version() or "TLS"
    tls.settimeout(timeout_s)
    try:
        if tls.recv(1) == b"":
            return RouterProbe(transport=RouterTransport.TLS,
                               detail=f"{version}, then the router {CLOSED_WITHOUT_ALERT}")
    except ssl.SSLError as exc:
        if "certificate" in str(exc).lower():
            return RouterProbe(transport=RouterTransport.MTLS,
                               detail=f"{version}, then the router demanded a client certificate: {exc}")
        return RouterProbe(transport=RouterTransport.TLS,
                           detail=f"{version} with no certificate alert: {exc}")
    except OSError:
        pass
    return RouterProbe(transport=RouterTransport.TLS,
                       detail=f"{version} completed with no client certificate")


def zenoh_override(endpoint: str, enclave_dir: Path | None) -> str:
    """A ZENOH_CONFIG_OVERRIDE for a client session, with the held enclave's certificate when given."""
    settings: list[tuple[str, object]] = [
        ("mode", "client"),
        ("listen/endpoints", []),
        ("connect/endpoints", [endpoint]),
    ]
    if enclave_dir is not None:
        tls = "transport/link/tls"
        settings += [
            (f"{tls}/root_ca_certificate", str(enclave_dir / "identity_ca.cert.pem")),
            (f"{tls}/connect_certificate", str(enclave_dir / "cert.pem")),
            (f"{tls}/connect_private_key", str(enclave_dir / "key.pem")),
            (f"{tls}/enable_mtls", True),
            # An attacker dials by address, so the router's name is not checked.
            (f"{tls}/verify_name_on_connect", False),
        ]
    return ";".join(f"{key}={json.dumps(value)}" for key, value in settings)
