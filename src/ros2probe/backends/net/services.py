import json
import logging
import socket
import ssl

from pydantic import BaseModel, ConfigDict
from websockets.exceptions import InvalidHandshake, WebSocketException
from websockets.sync.client import connect

from ...targets.profile import Robot, ServiceSpec

ROSAPI_TOPICS_CALL = {
    "op": "call_service",
    "service": "/rosapi/topics",
    "id": "ros2probe-topics",
}
MAX_REPLY_CHARS = 600
CONNECT_TIMEOUT_S = 2.0

LOG = logging.getLogger(__name__)
# Frame-level chatter from the rosbridge probe, which is not evidence about the
# target. Same treatment scapy gets in the wire backend.
logging.getLogger("websockets").setLevel(logging.INFO)


class PortState(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    port: int
    open: bool
    never_exposed: bool = False
    error: str = ""

    def __str__(self) -> str:
        return f"{self.name} ({self.port})"


class RosbridgeProbe(BaseModel):
    """What an unauthenticated WebSocket client got out of the bridge."""
    model_config = ConfigDict(frozen=True)

    uri: str = ""
    reachable: bool = False
    handshake_ok: bool = False
    topics: tuple[str, ...] = ()
    raw_reply: str = ""
    error: str = ""
    tls_error: str = ""

    @property
    def answered_as_anonymous(self) -> bool:
        return self.handshake_ok and bool(self.topics)

    def describe(self) -> str:
        if self.answered_as_anonymous:
            return (
                f"{self.uri} completed a WebSocket handshake with no "
                f"authentication and returned {len(self.topics)} topic name(s)"
            )
        if self.handshake_ok:
            return f"{self.uri} accepted an anonymous WebSocket connection"
        if self.tls_error:
            return f"{self.uri} refused TLS verification: {self.tls_error}"
        if self.reachable:
            return f"{self.uri} is open and is not a WebSocket endpoint: {self.error}"
        return f"{self.uri} not reachable: {self.error}"


class NetScan(BaseModel):
    model_config = ConfigDict(frozen=True)

    host: str
    ports: tuple[PortState, ...] = ()
    rosbridge: RosbridgeProbe | None = None

    @property
    def open_ports(self) -> tuple[PortState, ...]:
        return tuple(port for port in self.ports if port.open)

    @property
    def never_exposed_open(self) -> tuple[PortState, ...]:
        return tuple(port for port in self.open_ports if port.never_exposed)

    def summary(self) -> str:
        if not self.open_ports:
            return f"no scanned service ports open on {self.host}"
        return f"open on {self.host}: " + ", ".join(
            str(port) for port in self.open_ports
        )


def check_port(host: str, service: ServiceSpec, timeout_s: float) -> PortState:
    try:
        with socket.create_connection((host, service.port), timeout=timeout_s):
            return PortState(
                name=service.name, port=service.port, open=True,
                never_exposed=service.never_exposed,
            )
    except TimeoutError:
        return PortState(
            name=service.name, port=service.port, open=False,
            never_exposed=service.never_exposed, error="timeout",
        )
    except OSError as exc:
        return PortState(
            name=service.name, port=service.port, open=False,
            never_exposed=service.never_exposed, error=str(exc),
        )


def probe_rosbridge(
    host: str, service: ServiceSpec, timeout_s: float,
) -> RosbridgeProbe:
    """Open a WebSocket to rosbridge and ask `rosapi` for the topic list."""
    uri = f"{service.websocket_uri_scheme}://{host}:{service.port}"
    context = ssl.create_default_context() if service.tls else None

    try:
        with connect(
            uri,
            ssl=context,
            open_timeout=timeout_s,
            close_timeout=timeout_s,
            max_size=4 * 1024 * 1024,
        ) as websocket:
            websocket.send(json.dumps(ROSAPI_TOPICS_CALL))
            reply = websocket.recv(timeout=timeout_s)
    except ssl.SSLError as exc:
        return RosbridgeProbe(uri=uri, reachable=True, tls_error=str(exc))
    except InvalidHandshake as exc:
        # The port answered and is not a WebSocket endpoint, or refused the
        # upgrade. Either way it is reachable, which is worth reporting.
        return RosbridgeProbe(uri=uri, reachable=True, error=str(exc))
    except TimeoutError:
        return RosbridgeProbe(uri=uri, error="timeout")
    except WebSocketException as exc:
        return RosbridgeProbe(uri=uri, reachable=True, error=str(exc))
    except OSError as exc:
        return RosbridgeProbe(uri=uri, error=str(exc))

    text = reply if isinstance(reply, str) else reply.decode("utf-8", "replace")
    topics: tuple[str, ...] = ()
    try:
        values = json.loads(text).get("values") or {}
        topics = tuple(values.get("topics") or ())
    except (ValueError, AttributeError):
        pass

    return RosbridgeProbe(
        uri=uri, reachable=True, handshake_ok=True, topics=topics,
        raw_reply=text[:MAX_REPLY_CHARS],
    )


def scan(robot: Robot) -> NetScan:
    # The port we were given to connect over is authorized access, not an exposure.
    access_port = robot.ssh.port if robot.ssh else None
    ports = tuple(
        check_port(robot.address, service, CONNECT_TIMEOUT_S)
        for service in sorted(robot.services, key=lambda item: item.port)
        if service.port != access_port
    )
    bridge: RosbridgeProbe | None = None
    bridge_service = robot.service("rosbridge")
    if bridge_service is not None and any(
        port.open and port.port == bridge_service.port for port in ports
    ):
        bridge = probe_rosbridge(robot.address, bridge_service, CONNECT_TIMEOUT_S)
    result = NetScan(host=robot.address, ports=ports, rosbridge=bridge)
    LOG.debug("%s", result)
    return result
