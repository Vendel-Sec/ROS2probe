from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .files import FileFacts


class Family(StrEnum):
    FASTDDS = "fastdds"
    CYCLONE = "cyclone"
    ZENOH = "zenoh"


class Rmw(StrEnum):
    """The target's rmw, which decides the format of its profile at rest."""
    FASTRTPS = "rmw_fastrtps_cpp"
    FASTRTPS_DYNAMIC = "rmw_fastrtps_dynamic_cpp"
    CYCLONEDDS = "rmw_cyclonedds_cpp"
    ZENOH = "rmw_zenoh_cpp"

    @property
    def family(self) -> Family:
        return {Rmw.CYCLONEDDS: Family.CYCLONE, Rmw.ZENOH: Family.ZENOH}.get(self, Family.FASTDDS)


CYCLONE_RMWS = frozenset({Rmw.CYCLONEDDS})
ZENOH_RMWS = frozenset({Rmw.ZENOH})

# Every vendor's plugins are normalised to the DDS-Security class names.
EXPECTED_AUTH_PLUGIN = "builtin.PKI-DH"
EXPECTED_CRYPTO_PLUGIN = "builtin.AES-GCM-GMAC"
EXPECTED_ACCESS_PLUGIN = "builtin.Access-Permissions"

# The tree's mitigation names AUTO and the ECDH suites as acceptable. Anything
# pinned to plain finite-field DH is leaf A.1.7.
ACCEPTABLE_KEY_AGREEMENT = frozenset({
    "AUTO",
    "ECDH+PRIME256V1-CEUM",
    "ECDH+PRIME384V1-CEUM",
    "ECDH+PRIME521V1-CEUM",
})


class SettingNames(BaseModel):
    """Each setting's name in one vendor's file. Empty means the vendor has none."""
    model_config = ConfigDict(frozen=True)

    vendor: str
    auth_plugin: str
    crypto_plugin: str
    access_plugin: str
    identity_crl: str
    key_password: str
    key_agreement: str = ""
    legacy_algorithms: str = ""


class XmlProfile(BaseModel):
    """The security settings of one rmw profile, whichever vendor's. None means unset."""
    model_config = ConfigDict(frozen=True)

    path: Path
    facts: FileFacts
    names: SettingNames
    # Every setting the file declares, in the vendor's own spelling.
    declared: tuple[str, ...] = ()
    parse_error: str = ""

    auth_plugin: str | None = None
    crypto_plugin: str | None = None
    access_plugin: str | None = None
    identity_crl: str | None = None
    key_password: str | None = None
    key_agreement: str | None = None
    legacy_algorithms: str | None = None

    @property
    def vendor(self) -> str:
        return self.names.vendor

    @property
    def missing_plugins(self) -> tuple[str, ...]:
        """The plugins the file never instantiates, by the vendor's names."""
        return tuple(
            getattr(self.names, field) for field in
            ("auth_plugin", "crypto_plugin", "access_plugin")
            if getattr(self, field) is None
        )

    @property
    def key_agreement_is_acceptable(self) -> bool:
        configured = (self.key_agreement or "AUTO").strip().upper()
        return configured in ACCEPTABLE_KEY_AGREEMENT

    @property
    def advertises_legacy_algorithms(self) -> bool:
        return (self.legacy_algorithms or "false").strip().lower() == "true"


def is_cyclone(rmw: str) -> bool:
    return rmw in CYCLONE_RMWS


def is_zenoh(rmw: str) -> bool:
    return rmw in ZENOH_RMWS


def default_profile_filename(rmw: str) -> str:
    """The profile name looked for in a keystore, as the simulated target writes it."""
    return "cyclonedds.xml" if is_cyclone(rmw) else "fastdds_profile.xml"
