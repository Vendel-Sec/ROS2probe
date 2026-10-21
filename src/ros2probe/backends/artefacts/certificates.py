import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import BaseModel, ConfigDict


class Certificate(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    subject: str
    issuer: str
    not_before: dt.datetime
    not_after: dt.datetime
    serial: str
    key_algorithm: str            # "RSA" | "EC" | "unknown"
    key_bits: int | None = None
    curve: str | None = None
    fingerprint: str              # SHA-256, hex

    @property
    def lifetime_days(self) -> int:
        return (self.not_after - self.not_before).days

    @property
    def remaining_days(self) -> int:
        return (self.not_after - dt.datetime.now(dt.UTC)).days

    @property
    def expired(self) -> bool:
        return self.remaining_days < 0

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer

    @property
    def strength_summary(self) -> str:
        if self.key_algorithm == "RSA":
            return f"RSA-{self.key_bits}"
        if self.key_algorithm == "EC":
            return f"EC {self.curve}"
        return self.key_algorithm

    def meets_minimum(self, min_rsa_bits: int, min_ec_bits: int) -> bool:
        bits = self.key_bits or 0
        if self.key_algorithm == "RSA":
            return bits >= min_rsa_bits
        if self.key_algorithm == "EC":
            return bits >= min_ec_bits
        return False              # an unrecognised algorithm is not a pass

    def describe(self) -> str:
        return (
            f"{self.subject} issued by {self.issuer}, {self.strength_summary}, "
            f"{self.lifetime_days}d lifetime, {self.remaining_days}d remaining"
        )


def parse_certificate(path: Path) -> Certificate | None:
    try:
        cert = x509.load_pem_x509_certificate(path.read_bytes())
    except (OSError, ValueError):
        return None

    public_key = cert.public_key()
    algorithm, bits, curve = "unknown", None, None
    if isinstance(public_key, rsa.RSAPublicKey):
        algorithm, bits = "RSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        algorithm = "EC"
        bits = public_key.curve.key_size
        curve = public_key.curve.name

    return Certificate(
        path=path,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        serial=format(cert.serial_number, "x"),
        key_algorithm=algorithm, key_bits=bits, curve=curve,
        # SHA-256 always, so two certificates stay comparable by fingerprint
        # regardless of the algorithm each was signed with.
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
    )
