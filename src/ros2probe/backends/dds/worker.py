import sys
import time

import rclpy
from rclpy.node import Node
from rclpy.parameter_client import AsyncParameterClient
from rclpy.qos import (
    QoSDurabilityPolicy,
    QoSHistoryPolicy,
    QoSProfile,
    QoSReliabilityPolicy,
)
from rosidl_runtime_py.set_message import set_message_fields
from rosidl_runtime_py.utilities import get_message

from .protocol import (
    EndpointInfo,
    Job,
    JobKind,
    NodeInfo,
    ParamValue,
    TopicInfo,
    WorkerResult,
)

# Best-effort with a shallow queue, so a probe never becomes a load generator on a
# high-rate sensor topic and never blocks waiting for a reliable handshake.
PROBE_QOS = QoSProfile(
    history=QoSHistoryPolicy.KEEP_LAST,
    depth=5,
    reliability=QoSReliabilityPolicy.BEST_EFFORT,
    durability=QoSDurabilityPolicy.VOLATILE,
)

POLL_S = 0.2
MAX_SAMPLED_MESSAGES = 3
MESSAGE_SAMPLE_CHARS = 400


def spin_for(node: Node, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        rclpy.spin_once(node, timeout_sec=POLL_S)


# Tooling on the probe's own machine, not evidence about the target.
PROBE_SIDE_NODES = ("_ros2cli_daemon", "_ros2cli_")
PROBE_SIDE_TOPICS = ("/parameter_events", "/rosout")


def _remote_endpoints(getter, topic: str, own: tuple[str, str]) -> list | None:
    """Endpoints on a topic that are not the probe's own. None if the RMW cannot say."""
    try:
        infos = getter(topic)
    except Exception:
        return None
    return [
        info for info in infos
        if not (info.node_name == own[0] and info.node_namespace == own[1])
    ]


def observe_graph(node: Node, job: Job) -> WorkerResult:
    """What discovery hands us, excluding the probe's own participant."""
    spin_for(node, job.timeout_s)

    own = (node.get_name(), node.get_namespace())
    own_prefix = f"{own[1].rstrip('/')}/{own[0]}/"

    # The probe is itself a participant: ignore /rosout and /parameter_events
    own_publishers: dict[str, int] = {}
    for publisher in node.publishers:
        own_publishers[publisher.topic_name] = (
            own_publishers.get(publisher.topic_name, 0) + 1
        )
    own_subscriptions: dict[str, int] = {}
    for subscription in node.subscriptions:
        own_subscriptions[subscription.topic_name] = (
            own_subscriptions.get(subscription.topic_name, 0) + 1
        )

    nodes = tuple(
        NodeInfo(name=name, namespace=namespace)
        for name, namespace in node.get_node_names_and_namespaces()
        if (name, namespace) != own and not name.startswith(PROBE_SIDE_NODES)
    )

    topics = []
    for topic, types in node.get_topic_names_and_types():
        if topic in PROBE_SIDE_TOPICS:
            continue
        remote_pubs = _remote_endpoints(node.get_publishers_info_by_topic, topic, own)
        remote_subs = _remote_endpoints(
            node.get_subscriptions_info_by_topic, topic, own
        )
        if remote_pubs is None or remote_subs is None:
            publishers = node.count_publishers(topic) - own_publishers.get(topic, 0)
            subscribers = node.count_subscribers(topic) - own_subscriptions.get(topic, 0)
        else:
            publishers, subscribers = len(remote_pubs), len(remote_subs)
        if publishers <= 0 and subscribers <= 0:
            continue
        topics.append(
            TopicInfo(
                name=topic,
                types=tuple(types),
                publisher_count=max(publishers, 0),
                subscriber_count=max(subscribers, 0),
            )
        )

    services = tuple(
        name
        for name, _types in node.get_service_names_and_types()
        if not name.startswith(own_prefix)
    )
    return WorkerResult(
        participant_created=True,
        nodes=nodes,
        topics=tuple(topics),
        services=services,
    )


def observe_read(node: Node, job: Job) -> WorkerResult:
    """Whether this attacker position can subscribe and actually receive payloads."""
    message_type = get_message(job.type)
    received: list[str] = []

    def on_message(message: object) -> None:
        if len(received) < MAX_SAMPLED_MESSAGES:
            received.append(str(message)[:MESSAGE_SAMPLE_CHARS])

    node.create_subscription(message_type, job.topic, on_message, PROBE_QOS)
    spin_for(node, job.timeout_s)

    return WorkerResult(
        participant_created=True,
        messages_received=len(received),
        first_message=received[0] if received else "",
    )


def observe_write_match(node: Node, job: Job) -> WorkerResult:
    """Whether a legitimate reader will match this attacker's writer."""
    message_type = get_message(job.type)
    publisher = node.create_publisher(message_type, job.topic, PROBE_QOS)

    deadline = time.monotonic() + job.timeout_s
    matched = 0
    while time.monotonic() < deadline:
        rclpy.spin_once(node, timeout_sec=POLL_S)
        matched = publisher.get_subscription_count()
        if matched > 0:
            break

    subscriptions = tuple(
        EndpointInfo(
            node_name=info.node_name,
            node_namespace=info.node_namespace,
            topic_type=info.topic_type,
            endpoint_type=str(info.endpoint_type),
            gid=bytes(info.endpoint_gid).hex(),
        )
        for info in node.get_subscriptions_info_by_topic(job.topic)
    )

    # Only reached when the safety gate handed down a non-zero count.
    published = 0
    for _ in range(job.publish_count):
        message = message_type()
        if job.payload:
            set_message_fields(message, job.payload)
        publisher.publish(message)
        published += 1
        rclpy.spin_once(node, timeout_sec=POLL_S)

    return WorkerResult(
        participant_created=True,
        matched_subscriptions=matched,
        subscription_info=subscriptions,
        payloads_published=published,
    )


def observe_params(node: Node, job: Job) -> WorkerResult:
    """The parameter service on a remote node, which is leaf B.2.4."""
    client = AsyncParameterClient(node, job.target_node)
    if not client.wait_for_services(timeout_sec=job.timeout_s):
        return WorkerResult(
            participant_created=True,
            param_service_reachable=False,
            param_detail=f"no parameter service reachable on {job.target_node}",
        )

    listed: tuple[str, ...] = ()
    future = client.list_parameters()
    rclpy.spin_until_future_complete(node, future, timeout_sec=job.timeout_s)
    response = future.result()
    if response is not None:
        listed = tuple(response.result.names)

    read: list[ParamValue] = []
    if job.param_names:
        future = client.get_parameters(list(job.param_names))
        rclpy.spin_until_future_complete(node, future, timeout_sec=job.timeout_s)
        response = future.result()
        if response is not None:
            # strict: a service returning a different number of values than
            # names were asked for is a protocol violation, and pairing them
            # positionally anyway would report the wrong value against a name.
            for name, value in zip(job.param_names, response.values, strict=True):
                read.append(ParamValue(name=name, value=str(value)))

    return WorkerResult(
        participant_created=True,
        param_service_reachable=True,
        params_listed=listed,
        params_read=tuple(read),
    )


HANDLERS = {
    JobKind.GRAPH: observe_graph,
    JobKind.READ: observe_read,
    JobKind.WRITE_MATCH: observe_write_match,
    JobKind.PARAMS: observe_params,
}


def main() -> int:
    raw = sys.stdin.read()
    try:
        job = Job.model_validate_json(raw)
    except ValueError as exc:
        print(WorkerResult(ok=False, error=f"bad job: {exc}").model_dump_json())
        return 2

    node: Node | None = None
    try:
        # Anything after --ros-args is for rclpy, including --enclave.
        rclpy.init(args=sys.argv)
        node = Node(job.node_name)
        result = HANDLERS[job.kind](node, job)
        result = result.model_copy(update={"ok": True})
    except Exception as exc:
        # A refused participant is the most informative failure here, and it must
        # reach the parent as data rather than as a traceback on stderr.
        result = WorkerResult(ok=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        if node is not None:
            node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()

    print(result.model_dump_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
