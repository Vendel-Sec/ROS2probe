import stat
from pathlib import Path

from pydantic import BaseModel, ConfigDict

# Both forms of encrypted private key PEM that appear in practice.
PKCS8_ENCRYPTED_HEADER = "ENCRYPTED PRIVATE KEY"
LEGACY_ENCRYPTED_HEADER = "Proc-Type: 4,ENCRYPTED"
PEM_HEADER_BYTES = 400


class FileFacts(BaseModel):
    """Mode and ownership for one path, for the custody leaves."""
    model_config = ConfigDict(frozen=True)

    path: Path
    exists: bool
    mode: int = 0
    uid: int = -1
    gid: int = -1

    @property
    def mode_octal(self) -> str:
        return format(self.mode & 0o7777, "04o")

    @property
    def group_or_world_readable(self) -> bool:
        return bool(self.mode & (stat.S_IRGRP | stat.S_IROTH))

    @property
    def group_or_world_writable(self) -> bool:
        return bool(self.mode & (stat.S_IWGRP | stat.S_IWOTH))

    @property
    def world_readable(self) -> bool:
        return bool(self.mode & stat.S_IROTH)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    def describe(self) -> str:
        if not self.exists:
            return f"{self.path} does not exist"
        return f"{self.path} mode {self.mode_octal} uid {self.uid} gid {self.gid}"


def file_facts(path: Path) -> FileFacts:
    try:
        info = path.stat()
    except OSError:
        return FileFacts(path=path, exists=False)
    return FileFacts(
        path=path, exists=True, mode=info.st_mode,
        uid=info.st_uid, gid=info.st_gid,
    )


def key_is_encrypted(path: Path) -> bool | None:
    """Whether a private key PEM is passphrase-encrypted at rest, None when unreadable."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(PEM_HEADER_BYTES)
    except OSError:
        return None
    return PKCS8_ENCRYPTED_HEADER in head or LEGACY_ENCRYPTED_HEADER in head
