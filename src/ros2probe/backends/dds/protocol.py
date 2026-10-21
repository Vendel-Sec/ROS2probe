from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class JobKind(StrEnum):
    GRAPH = "graph"
    READ = "read"
    WRITE_MATCH = "write_match"
    PARAMS = "params"


class Job(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: JobKind
    timeout_s: float = 8.0
    node_name: str = "probe_observer"

    # read and write_match
    topic: str = ""
    type: str = ""
    publish_count: int = 0
    # A ROS message field tree, handed to rosidl's set_message_fields. The one
    # place a free-form mapping is the right shape, because the structure belongs
    # to the message rather than to this suite.
    payload: dict[str, Any] = Field(default_factory=dict)

    # params. Read only: this suite does not write parameters. Reaching the
    # parameter service at all is what leaf B.2.4 is about, and a safety limit
    # changed on a real machine is not a test result worth having.
    target_node: str = ""
    param_names: tuple[str, ...] = ()


class ParamValue(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    value: str


class EndpointInfo(BaseModel):
    """A remote endpoint that matched, or was seen on, a topic."""
    model_config = ConfigDict(frozen=True)

    node_name: str = ""
    node_namespace: str = ""
    topic_type: str = ""
    endpoint_type: str = ""
    gid: str = ""

    def describe(self) -> str:
        namespace = self.node_namespace.rstrip("/")
        return f"{namespace}/{self.node_name} gid={self.gid[:16]}"


class TopicInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    types: tuple[str, ...] = ()
    publisher_count: int = 0
    subscriber_count: int = 0


class NodeInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    namespace: str = "/"

    @property
    def full(self) -> str:
        return f"{self.namespace.rstrip('/')}/{self.name}"


class WorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = False
    error: str = ""
    participant_created: bool = False

    # graph
    nodes: tuple[NodeInfo, ...] = ()
    topics: tuple[TopicInfo, ...] = ()
    services: tuple[str, ...] = ()

    # read
    messages_received: int = 0
    first_message: str = ""

    # write_match
    matched_subscriptions: int = 0
    subscription_info: tuple[EndpointInfo, ...] = ()
    payloads_published: int = 0

    # params
    params_listed: tuple[str, ...] = ()
    params_read: tuple[ParamValue, ...] = ()
    param_service_reachable: bool = False
    param_detail: str = ""

    # Zenoh probe only: the router turned the probe away before any session existed.
    refused_by_router: bool = False
    router_detail: str = ""

    # diagnostics
    stderr_tail: str = ""

    @property
    def saw_anything(self) -> bool:
        return bool(self.nodes or self.topics or self.services)

    @property
    def node_names(self) -> tuple[str, ...]:
        return tuple(sorted(node.full for node in self.nodes))

    @property
    def topic_names(self) -> tuple[str, ...]:
        return tuple(sorted(topic.name for topic in self.topics))

    def undecided_reason(self) -> str:
        """Why a test should skip rather than pass on this result."""
        detail = self.error or "unknown reason"
        if self.stderr_tail:
            detail = f"{detail}\n    worker stderr: {self.stderr_tail}"
        return detail
