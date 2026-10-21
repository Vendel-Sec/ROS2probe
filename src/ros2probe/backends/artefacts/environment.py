import logging
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

ENABLE_REQUIRED_VALUE = "true"
STRATEGY_REQUIRED_VALUE = "Enforce"
DEFAULT_DOMAIN_ID = 0

LOG = logging.getLogger(__name__)


class EnvSource(StrEnum):
    """Where the values came from, which sets how much they are worth."""
    UNIT = "systemd-unit"        # authoritative for what the robot does at boot
    PROCESS = "running-process"  # /proc/<pid>/environ, the strongest evidence
    ENV_FILE = "env-file"        # a capture from the target
    SHELL = "shell-profile"      # a guess, and the tree says so
    UNKNOWN = "unknown"

    @property
    def trust_note(self) -> str:
        return {
            EnvSource.UNIT: "systemd unit, authoritative for boot",
            EnvSource.PROCESS: "the running process, strongest available evidence",
            EnvSource.ENV_FILE: "a captured env file",
            EnvSource.SHELL: "a shell profile, which is NOT what the robot boots with",
            EnvSource.UNKNOWN: "unknown provenance",
        }[self]


class RuntimeEnv(BaseModel):
    """The security-relevant environment of the target's ROS processes."""
    model_config = ConfigDict(frozen=True)

    source: EnvSource = EnvSource.UNKNOWN
    origin: str = ""

    security_enable: str | None = None
    security_strategy: str | None = None
    security_keystore: str | None = None
    security_enclave_override: str | None = None
    domain_id: str | None = None
    rmw_implementation: str | None = None
    fastdds_profiles_file: str | None = None
    # A path, a file:// URI, a list of either, or inline XML. Recorded, not opened.
    cyclonedds_uri: str | None = None
    zenoh_router_config_uri: str | None = None
    zenoh_session_config_uri: str | None = None
    # Overrides any key of either Zenoh config, outranking the file.
    zenoh_config_override: str | None = None

    @classmethod
    def from_variables(
        cls, variables: dict[str, str], source: EnvSource, origin: str,
    ) -> "RuntimeEnv":
        fields = {FIELD_FOR_VARIABLE[k]: v for k, v in variables.items() if k in FIELD_FOR_VARIABLE}
        parsed = cls(source=source, origin=origin, **fields)
        LOG.debug("%s", parsed)
        return parsed

    def display(self, variable: str) -> str:
        """A form for failure messages that distinguishes absent from empty."""
        field = FIELD_FOR_VARIABLE.get(variable)
        value = getattr(self, field) if field else None
        if value is None:
            return "<unset>"
        if value == "":
            return "<empty string>"
        return value

    # --- the A.0 family, named rather than stringly typed ------------------- #

    @property
    def security_enabled(self) -> bool:
        """Exactly the lowercase string "true"."""
        return self.security_enable == ENABLE_REQUIRED_VALUE

    @property
    def strategy_enforces(self) -> bool:
        return self.security_strategy == STRATEGY_REQUIRED_VALUE

    @property
    def keystore_path(self) -> Path | None:
        return Path(self.security_keystore) if self.security_keystore else None

    @property
    def enclave_override_in_force(self) -> bool:
        return bool(self.security_enclave_override)

    @property
    def domain(self) -> int | None:
        if self.domain_id is None or not self.domain_id.strip().isdigit():
            return None
        return int(self.domain_id.strip())

    @property
    def domain_is_default(self) -> bool:
        return self.domain is None or self.domain == DEFAULT_DOMAIN_ID

    @property
    def provenance(self) -> str:
        """One line for a failure message, so a reader knows how much to trust it."""
        return f"{self.origin or self.source.value} ({self.source.trust_note})"


# Environment variable name to model field. Declared once, used by both the
# parser and the display helper so the two cannot disagree.
FIELD_FOR_VARIABLE: dict[str, str] = {
    "ROS_SECURITY_ENABLE": "security_enable",
    "ROS_SECURITY_STRATEGY": "security_strategy",
    "ROS_SECURITY_KEYSTORE": "security_keystore",
    "ROS_SECURITY_ENCLAVE_OVERRIDE": "security_enclave_override",
    "ROS_DOMAIN_ID": "domain_id",
    "RMW_IMPLEMENTATION": "rmw_implementation",
    "FASTRTPS_DEFAULT_PROFILES_FILE": "fastdds_profiles_file",
    "CYCLONEDDS_URI": "cyclonedds_uri",
    "ZENOH_ROUTER_CONFIG_URI": "zenoh_router_config_uri",
    "ZENOH_SESSION_CONFIG_URI": "zenoh_session_config_uri",
    "ZENOH_CONFIG_OVERRIDE": "zenoh_config_override",
}
