import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..backends.artefacts.rmw_config import Rmw, is_cyclone, is_zenoh

# RTPS default port mapping: domain N gets 7400 + 250*N, and 232 is the last that fits.
PORT_BASE = 7400
DOMAIN_GAIN = 250
DomainId = Annotated[int, Field(ge=0, le=232)]
# "RTPS" as the first four bytes of the UDP payload, for a BPF filter.
RTPS_MAGIC_BPF = int.from_bytes(b"RTPS", "big")
ZENOH_ROUTER_PORT = 7447

class Transport(StrEnum):
    NONE = "none"
    SSH = "ssh"


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TopicSpec(Strict):
    name: str
    type: str = ""

    @property
    def dds_name(self) -> str:
        return "rt/" + self.name.lstrip("/")


class ParamSpec(Strict):
    node: str
    name: str


class ServiceSpec(Strict):
    name: str
    port: int
    # Has no business being reachable on a robot segment at all.
    never_exposed: bool = False
    tls: bool = False

    @property
    def websocket_uri_scheme(self) -> str:
        return "wss" if self.tls else "ws"


DEFAULT_SERVICES = (
    ServiceSpec(name="rosbridge", port=9090),
    ServiceSpec(name="foxglove", port=8765),
    ServiceSpec(name="vnc", port=5900, never_exposed=True),
    ServiceSpec(name="rdp", port=3389, never_exposed=True),
    ServiceSpec(name="ssh", port=22, never_exposed=True),
    ServiceSpec(name="mqtt", port=1883, never_exposed=True),
    ServiceSpec(name="docker-api", port=2375, never_exposed=True),
    ServiceSpec(name="web-teleop", port=8080),
)


class Ssh(Strict):
    user: str = ""
    port: int = 22
    identity: Path | None = None
    password: str = ""
    # Pins the host key. Unset, the first connection trusts whatever answers.
    known_hosts: Path | None = None
    # Run host commands through `sudo -n`, for the reads that need root: another
    # account's /proc/<pid>/environ, a keystore only root and ROS can enter. The
    # leaves about the login account itself still run as it.
    sudo: bool = False


class Robot(Strict):
    """The machine. Every test that opens a connection opens it to `address`."""
    address: str
    ssh: Ssh | None = None
    ros_user: str = "ros"
    ros_process_pattern: str = "robot_graph|ros2|_ros2_daemon"
    workspace: str = ""
    unit: str = ""
    # Paths on the robot itself.
    keystore: str = ""
    profile: str = ""
    services: tuple[ServiceSpec, ...] = DEFAULT_SERVICES

    @property
    def transport(self) -> Transport:
        return Transport.SSH if self.ssh else Transport.NONE

    def service(self, name: str) -> ServiceSpec | None:
        return next((s for s in self.services if s.name == name), None)


class Ros(Strict):
    """The graph."""
    rmw: Rmw = Rmw.FASTRTPS
    domain: DomainId = 0
    # For leaf A.0.6. Each one costs a discovery timeout.
    domain_scan: tuple[DomainId, ...] = (0, 1, 42)
    # Topic name to message type. Every other topic is discovered.
    actuation: dict[str, str] = Field(default_factory=dict)
    # Message fields published with --arm --allow-actuation-payload. Unset fields are zero.
    payloads: dict[str, dict[str, Any]] = Field(default_factory=dict)
    params: tuple[ParamSpec, ...] = ()

    @model_validator(mode="after")
    def _payloads_are_actuation(self) -> "Ros":
        unknown = set(self.payloads) - set(self.actuation)
        if unknown:
            raise ValueError(f"payloads for topics not in actuation: {', '.join(sorted(unknown))}")
        return self

    @property
    def actuation_topics(self) -> tuple[TopicSpec, ...]:
        return tuple(TopicSpec(name=n, type=t) for n, t in self.actuation.items())

    def params_for(self, node: str) -> tuple[ParamSpec, ...]:
        return tuple(p for p in self.params if p.node == node)


class Credentials(Strict):
    """A credential the client handed over, for the T2 tests."""
    keystore: Path
    enclave: str


class Copies(Strict):
    """Files copied off the robot, for the static tests."""
    keystore: Path | None = None
    profile: Path | None = None
    router_config: Path | None = None


class Wire(Strict):
    interface: str = "any"
    # Decode this capture instead of taking one.
    pcap: Path | None = None


class WireSettings(BaseModel):
    """What the wire backend captures, derived from the profile."""
    interface: str
    pcap: Path | None
    domains: tuple[int, ...]
    # Cyclone's unicast ports are ephemeral, so also match the RTPS magic.
    payload_match: bool
    capture_seconds: float = 12.0
    max_packets: int = 4000

    @property
    def port_ranges(self) -> tuple[tuple[int, int], ...]:
        lows = (PORT_BASE + DOMAIN_GAIN * d for d in sorted(set(self.domains)))
        return tuple((low, low + DOMAIN_GAIN - 1) for low in lows)

    @property
    def capture_filter(self) -> str:
        clauses = [f"udp portrange {low}-{high}" for low, high in self.port_ranges]
        if self.payload_match:
            clauses.append(f"(udp and udp[8:4] = {RTPS_MAGIC_BPF:#010x})")
        return " or ".join(clauses)

    def covers(self, port: int) -> bool:
        return any(low <= port <= high for low, high in self.port_ranges)


def anchor(value: Path | None, base: Path) -> Path | None:
    """Expand $VARS and ~, then resolve a still-relative path against `base`."""
    if value is None:
        return None
    expanded = Path(os.path.expandvars(str(value))).expanduser()
    return expanded if expanded.is_absolute() else (base / expanded).resolve()


class TargetProfile(Strict):
    name: str
    robot: Robot
    ros: Ros = Field(default_factory=Ros)
    credentials: Credentials | None = None
    copies: Copies = Field(default_factory=Copies)
    wire: Wire = Field(default_factory=Wire)

    @property
    def zenoh(self) -> bool:
        return is_zenoh(self.ros.rmw)

    @property
    def probe_rmw(self) -> str:
        """Zenoh needs a Zenoh probe. Fast DDS and Cyclone interoperate, so keep the runner's."""
        return self.ros.rmw if self.zenoh else ""

    @property
    def zenoh_router(self) -> str:
        return f"{self.robot.address}:{ZENOH_ROUTER_PORT}" if self.zenoh else ""

    @property
    def capture(self) -> WireSettings:
        return WireSettings(
            interface=self.wire.interface, pcap=self.wire.pcap,
            domains=(self.ros.domain, *self.ros.domain_scan),
            payload_match=is_cyclone(self.ros.rmw),
        )

    @classmethod
    def load(cls, path: Path | str) -> "TargetProfile":
        path = Path(path)
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"target profile must be a YAML mapping: {path}")
        raw.setdefault("name", path.stem)
        profile = cls.model_validate(raw)
        base = path.parent
        for section, fields in ((profile.copies, ("keystore", "profile", "router_config")),
                                (profile.wire, ("pcap",)), (profile.credentials, ("keystore",)),
                                (profile.robot.ssh, ("identity", "known_hosts"))):
            for field in fields if section else ():
                setattr(section, field, anchor(getattr(section, field), base))
        return profile
