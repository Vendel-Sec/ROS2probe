import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .certificates import Certificate, parse_certificate
from .cyclonedds_config import parse_cyclonedds_config
from .fastdds_profile import parse_fastdds_profile
from .files import FileFacts, file_facts, key_is_encrypted
from .governance import Governance, parse_governance
from .permissions import Permissions, parse_permissions
from .rmw_config import Rmw, XmlProfile, default_profile_filename, is_cyclone, is_zenoh
from .zenoh_config import (
    ROUTER_FILENAME,
    SESSION_FILENAME,
    ZenohConfig,
    parse_zenoh_config,
)

IDENTITY_CA_NAMES = ("identity_ca.cert.pem", "ca.cert.pem")
PERMISSIONS_CA_NAMES = ("permissions_ca.cert.pem", "ca.cert.pem")
CRL_FILENAME = "identity_crl.pem"
PASSPHRASE_FILENAME = "key.pass"
RCL_TOPICS = frozenset({"rt/rosout", "rt/parameter_events"})

LOG = logging.getLogger(__name__)


class Enclave(BaseModel):
    """One directory under `enclaves/`, holding one node's identity and grant."""
    model_config = ConfigDict(frozen=True)

    name: str                     # "/scan_publisher"
    path: Path
    certificate: Certificate | None = None
    key: FileFacts
    key_encrypted: bool | None = None
    passphrase_file: FileFacts
    governance: Governance | None = None
    permissions: Permissions | None = None
    profile: XmlProfile | None = None
    zenoh_session: ZenohConfig | None = None
    identity_ca: Certificate | None = None
    permissions_ca: Certificate | None = None
    crl_present: bool = False

    @property
    def passphrase_is_leaked_beside_key(self) -> bool:
        return self.passphrase_file.exists


class Keystore(BaseModel):
    """A parsed keystore tree. Built by `read_keystore`."""
    model_config = ConfigDict(frozen=True)

    root: Path
    facts: FileFacts
    public_dir: FileFacts
    private_dir: FileFacts
    identity_ca: Certificate | None = None
    permissions_ca: Certificate | None = None
    ca_private_keys: tuple[FileFacts, ...] = ()
    enclaves: tuple[Enclave, ...] = ()
    top_profile: XmlProfile | None = None
    top_zenoh_session: ZenohConfig | None = None
    zenoh_router: ZenohConfig | None = None
    errors: tuple[str, ...] = Field(default=())

    @property
    def identity_and_permissions_ca_are_same(self) -> bool:
        if self.identity_ca is None or self.permissions_ca is None:
            return False
        return self.identity_ca.fingerprint == self.permissions_ca.fingerprint

    def enclave(self, name: str) -> Enclave | None:
        for item in self.enclaves:
            if item.name == name:
                return item
        return None

    @property
    def any_governance(self) -> Governance | None:
        for item in self.enclaves:
            if item.governance is not None:
                return item.governance
        return None

    @property
    def all_permissions(self) -> tuple[Permissions, ...]:
        return tuple(
            item.permissions for item in self.enclaves if item.permissions is not None
        )

    @property
    def topics(self) -> tuple[str, ...]:
        """Application topics any enclave is granted. rt/ is the ROS 2 topic prefix, the rest are services and rcl's own."""
        granted = set().union(*(p.allowed_topics for p in self.all_permissions))
        return tuple(sorted(t for t in granted if t.startswith("rt/") and t not in RCL_TOPICS))

    @property
    def any_profile(self) -> XmlProfile | None:
        if self.top_profile is not None:
            return self.top_profile
        for item in self.enclaves:
            if item.profile is not None:
                return item.profile
        return None

    @property
    def all_profiles(self) -> tuple[XmlProfile, ...]:
        found = [self.top_profile] if self.top_profile is not None else []
        found.extend(item.profile for item in self.enclaves if item.profile is not None)
        return tuple(found)

    @property
    def all_zenoh_configs(self) -> tuple[ZenohConfig, ...]:
        found = [c for c in (self.zenoh_router, self.top_zenoh_session) if c is not None]
        found.extend(item.zenoh_session for item in self.enclaves if item.zenoh_session is not None)
        return tuple(found)

    @property
    def all_certificates(self) -> tuple[tuple[str, Certificate], ...]:
        """Every certificate with a label, for the lifetime and key-size tests."""
        found: list[tuple[str, Certificate]] = []
        for item in self.enclaves:
            if item.certificate is not None:
                found.append((item.name, item.certificate))
        if self.identity_ca is not None:
            found.append(("identity CA", self.identity_ca))
        if self.permissions_ca is not None and not self.identity_and_permissions_ca_are_same:
            found.append(("permissions CA", self.permissions_ca))
        return tuple(found)


def parse_rmw_config(path: Path, rmw: str) -> XmlProfile | None:
    """The file at `path`, read as the target's rmw would read it. Zenoh has no XmlProfile."""
    if is_zenoh(rmw):
        return None
    if is_cyclone(rmw):
        return parse_cyclonedds_config(path)
    return parse_fastdds_profile(path)


def _rglob(base: Path, pattern: str) -> tuple[list[Path], tuple[str, ...]]:
    """rglob() that reports a permission problem instead of raising."""
    try:
        return list(base.rglob(pattern)), ()
    except OSError as error:
        return [], (f"cannot walk {base}: {error.strerror}",)


def _is_dir(path: Path) -> tuple[bool, tuple[str, ...]]:
    """is_dir() that reports a permission problem instead of raising."""
    try:
        return path.is_dir(), ()
    except OSError as error:
        return False, (f"cannot stat {path}: {error.strerror}",)


def _first_existing(
    base: Path, names: tuple[str, ...],
) -> tuple[Path | None, tuple[str, ...]]:
    # Path.exists() swallows ENOENT but propagates EACCES, so an artefact copy
    # the runner cannot read raises here. That has to become a recorded error
    # and therefore a skip: "I could not read it" is not "it is not there", and
    # reporting the second would be a finding the run did not earn.
    problems: list[str] = []
    for name in names:
        candidate = base / name
        try:
            if candidate.exists():
                return candidate, tuple(problems)
        except OSError as error:
            problems.append(f"cannot read {candidate}: {error.strerror}")
    return None, tuple(problems)


def read_keystore(
    root: Path,
    rmw: str = Rmw.FASTRTPS,
    profile_path: Path | None = None,
    zenoh_router_path: Path | None = None,
) -> Keystore:
    """The keystore at `root`, with profiles read as `rmw` and the top one at `profile_path`."""
    profile_name = default_profile_filename(rmw)
    zenoh = is_zenoh(rmw)
    public = root / "public"
    private = root / "private"
    enclaves_dir = root / "enclaves"
    errors: list[str] = []

    root_is_dir, problems = _is_dir(root)
    if not root_is_dir:
        return Keystore(
            root=root,
            facts=file_facts(root),
            public_dir=file_facts(public),
            private_dir=file_facts(private),
            errors=problems or (f"keystore root does not exist: {root}",),
        )

    identity_ca_path, problems = _first_existing(public, IDENTITY_CA_NAMES)
    errors.extend(problems)
    permissions_ca_path, problems = _first_existing(public, PERMISSIONS_CA_NAMES)
    errors.extend(problems)
    if identity_ca_path is None:
        errors.append(f"no identity CA certificate under {public}")

    ca_private_keys: list[FileFacts] = []
    private_is_dir, problems = _is_dir(private)
    errors.extend(problems)
    if private_is_dir:
        key_paths, problems = _rglob(private, "*.pem")
        errors.extend(problems)
        ca_private_keys = [
            file_facts(path)
            for path in sorted(key_paths)
            if "key" in path.name.lower()
        ]

    enclaves: list[Enclave] = []
    enclaves_is_dir, problems = _is_dir(enclaves_dir)
    errors.extend(problems)
    if not enclaves_is_dir:
        errors.append(f"no enclaves directory under {root}")
    else:
        cert_paths, problems = _rglob(enclaves_dir, "cert.pem")
        errors.extend(problems)
        for cert_path in sorted(cert_paths):
            directory = cert_path.parent
            name = "/" + directory.relative_to(enclaves_dir).as_posix()
            local_permissions_ca, problems = _first_existing(
                directory, ("permissions_ca.cert.pem",),
            )
            errors.extend(problems)
            local_permissions_ca = local_permissions_ca or permissions_ca_path
            governance_path = directory / "governance.p7s"
            permissions_path = directory / "permissions.p7s"

            enclaves.append(Enclave(
                name=name,
                path=directory,
                certificate=parse_certificate(cert_path),
                key=file_facts(directory / "key.pem"),
                key_encrypted=key_is_encrypted(directory / "key.pem"),
                passphrase_file=file_facts(directory / PASSPHRASE_FILENAME),
                governance=(
                    parse_governance(governance_path, local_permissions_ca)
                    if governance_path.exists() else None
                ),
                permissions=(
                    parse_permissions(permissions_path, local_permissions_ca)
                    if permissions_path.exists() else None
                ),
                profile=parse_rmw_config(directory / profile_name, rmw),
                zenoh_session=(
                    parse_zenoh_config(directory / SESSION_FILENAME) if zenoh else None
                ),
                identity_ca=parse_certificate(directory / "identity_ca.cert.pem"),
                permissions_ca=(
                    parse_certificate(local_permissions_ca)
                    if local_permissions_ca else None
                ),
                crl_present=(directory / CRL_FILENAME).exists(),
            ))
        if not enclaves:
            errors.append(f"no enclaves with a cert.pem under {enclaves_dir}")

    parsed = Keystore(
        root=root,
        facts=file_facts(root),
        public_dir=file_facts(public),
        private_dir=file_facts(private),
        identity_ca=parse_certificate(identity_ca_path) if identity_ca_path else None,
        permissions_ca=(
            parse_certificate(permissions_ca_path) if permissions_ca_path else None
        ),
        ca_private_keys=tuple(ca_private_keys),
        enclaves=tuple(enclaves),
        top_profile=parse_rmw_config(profile_path or root / profile_name, rmw),
        top_zenoh_session=(
            parse_zenoh_config(profile_path or root / SESSION_FILENAME) if zenoh else None
        ),
        zenoh_router=(
            parse_zenoh_config(zenoh_router_path or root / ROUTER_FILENAME)
            if zenoh else None
        ),
        errors=tuple(dict.fromkeys(errors)),
    )
    LOG.debug("%s", parsed)
    return parsed
