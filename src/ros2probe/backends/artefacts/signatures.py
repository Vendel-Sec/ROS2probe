import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict

SMIME_MULTIPART_MARKER = "application/x-pkcs7-signature"
# `ros2 security create_keystore` signs opaquely: the document lives inside the
# PKCS7 and the part is typed x-pkcs7-mime, not x-pkcs7-signature. Missing this
# form reports every real sros2 keystore as unsigned, which is A.3.16 and A.3.17
# raised against a robot that is correctly signed.
SMIME_OPAQUE_MARKER = "application/x-pkcs7-mime"
PEM_PKCS7_MARKER = "-----BEGIN PKCS7-----"
VERIFY_TIMEOUT_S = 15.0


class Signature(BaseModel):
    """The result of actually verifying a .p7s, not just noticing one."""
    model_config = ConfigDict(frozen=True)

    present: bool
    verified: bool
    form: str = ""       # "multipart" | "opaque" | "pem-pkcs7" | ""
    detail: str = ""

    @property
    def trustworthy(self) -> bool:
        return self.present and self.verified


def verify_signature(path: Path, ca_certificate: Path | None) -> Signature:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Signature(
            present=False, verified=False, detail=f"unreadable: {path}",
        )

    if PEM_PKCS7_MARKER in text:
        form, input_form = "pem-pkcs7", "PEM"
    elif SMIME_MULTIPART_MARKER in text.lower():
        form, input_form = "multipart", "SMIME"
    elif SMIME_OPAQUE_MARKER in text.lower():
        form, input_form = "opaque", "SMIME"
    else:
        return Signature(
            present=False, verified=False,
            detail="no S/MIME wrapper and no PKCS7 block, the document is unsigned",
        )

    if ca_certificate is None or not ca_certificate.exists():
        return Signature(
            present=True, verified=False, form=form,
            detail="signature present, and no Permissions CA certificate was "
                   "available to verify it against",
        )

    try:
        proc = subprocess.run(
            [
                "openssl", "smime", "-verify", "-in", str(path),
                "-inform", input_form, "-CAfile", str(ca_certificate),
                "-purpose", "any", "-out", "/dev/null",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=VERIFY_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Signature(
            present=True, verified=False, form=form,
            detail=f"signature present, verification could not run: {exc}",
        )

    if proc.returncode == 0:
        return Signature(
            present=True, verified=True, form=form,
            detail=f"verified against {ca_certificate.name}",
        )

    output = proc.stdout.strip().splitlines()
    return Signature(
        present=True, verified=False, form=form,
        detail=f"signature present but did NOT verify against "
               f"{ca_certificate.name}: {output[-1] if output else 'unknown error'}",
    )
