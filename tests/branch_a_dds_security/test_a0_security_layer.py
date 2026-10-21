import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import Keystore, RuntimeEnv
from ros2probe.backends.artefacts.rmw_config import Family
from ros2probe.backends.dds import DdsClient
from ros2probe.backends.host import HostShell
from ros2probe.targets.profile import TargetProfile


@leaf("A.0.1")
@pytest.mark.host
def test_security_enable_is_exactly_true(target_env: RuntimeEnv) -> None:
    """ROS_SECURITY_ENABLE must be the exact lowercase string "true"."""
    assert target_env.security_enabled, \
        f"ROS_SECURITY_ENABLE = {target_env.display('ROS_SECURITY_ENABLE')}, from {target_env.provenance}"


@leaf("A.0.1")
@pytest.mark.host
def test_configured_keystore_is_the_one_in_use(
    host: HostShell, profile: TargetProfile,
) -> None:
    """Every ROS process must load the same keystore, and it must be robot.keystore."""
    pids = host.ros_process_pids()
    if not pids:
        pytest.skip(f"no process matching {profile.robot.ros_process_pattern!r}")
    live = host.live_keystores(pids)
    if not live:
        pytest.skip(f"cannot read the environment of ROS processes {pids}")
    in_use = set(live.values())

    assert in_use != {""}, "no ROS process has ROS_SECURITY_KEYSTORE set"
    assert len(in_use) == 1, f"ROS processes load different keystores: {dict(sorted(live.items()))}"
    actual = in_use.pop()

    assert profile.robot.keystore, f"robot.keystore unset, nodes load {actual}"
    configured = host.realpath(profile.robot.keystore)
    assert configured == actual, f"robot.keystore is {configured}, nodes load {actual}"


@leaf("A.0.2")
@pytest.mark.host
def test_security_strategy_is_enforce(target_env: RuntimeEnv) -> None:
    """ROS_SECURITY_STRATEGY must be Enforce."""
    assert target_env.strategy_enforces, \
        f"ROS_SECURITY_STRATEGY = {target_env.display('ROS_SECURITY_STRATEGY')}, from {target_env.provenance}"


@leaf("A.0.3")
@pytest.mark.static
@pytest.mark.host
def test_keystore_is_not_attacker_writable(
    target_env: RuntimeEnv, keystore: Keystore,
) -> None:
    """The keystore must not be group or world writable, nor live under a user-writable prefix."""
    facts = keystore.facts
    path = str(target_env.keystore_path or keystore.root)

    assert not facts.group_or_world_writable, \
        f"{keystore.root} mode {facts.mode_octal} uid {facts.uid} gid {facts.gid}"
    assert not path.startswith(("/tmp/", "/var/tmp/", "/home/", "/dev/shm/")), \
        f"keystore under a user-writable prefix: {path}"


@leaf("A.0.4")
@pytest.mark.host
def test_no_enclave_override_in_force(target_env: RuntimeEnv) -> None:
    """ROS_SECURITY_ENCLAVE_OVERRIDE must be unset."""
    assert not target_env.security_enclave_override, \
        f"ROS_SECURITY_ENCLAVE_OVERRIDE = {target_env.display('ROS_SECURITY_ENCLAVE_OVERRIDE')}, " \
        f"from {target_env.provenance}"


@leaf("A.0.5")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_all_three_plugin_properties_are_present(keystore: Keystore) -> None:
    """The auth, crypto and access-control plugin properties must all be present in the rmw profile."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")

    missing = profile.missing_plugins
    assert not missing, f"{profile.path}: missing {', '.join(missing)}"


@leaf("A.0.6")
@pytest.mark.host
def test_domain_id_is_not_the_default(target_env: RuntimeEnv) -> None:
    """ROS_DOMAIN_ID must not be left at 0."""
    assert not target_env.domain_is_default, \
        f"ROS_DOMAIN_ID = {target_env.display('ROS_DOMAIN_ID')}, from {target_env.provenance}"


@leaf("A.0.6")
@pytest.mark.dds
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_no_graph_answers_on_a_scanned_domain(
    dds: DdsClient, profile: TargetProfile,
) -> None:
    """Sweeping a short list of domain IDs must find nothing."""
    domains = profile.ros.domain_scan
    if not domains:
        pytest.skip("ros.domain_scan is empty")

    answered: list[str] = []
    undecided = 0
    for domain, result in dds.scan_domains():
        if not result.participant_created:
            undecided += 1
        elif result.saw_anything:
            answered.append(
                f"domain {domain}: {len(result.nodes)} nodes, {len(result.topics)} topics "
                f"{', '.join(result.node_names[:6])}"
            )
    if undecided == len(domains):
        pytest.skip("undecided: no participant on any domain")

    assert not answered, "\n".join(answered)


@leaf("A.0.1")
@pytest.mark.dds
def test_unauthenticated_participant_cannot_discover_the_graph(
    dds: DdsClient,
) -> None:
    """An unauthenticated participant on the segment must not discover any node or topic."""
    result = dds.anonymous_graph()
    if result.refused_by_router:
        return
    if not result.participant_created:
        pytest.skip(f"undecided: {result.error}")

    assert not result.saw_anything, \
        f"nodes: {', '.join(result.node_names[:10]) or 'none'}\n" \
        f"topics: {', '.join(result.topic_names[:14]) or 'none'}"
