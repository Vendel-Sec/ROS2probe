import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import is_cyclone, is_zenoh
from ros2probe.backends.dds import DdsClient
from ros2probe.backends.dds.session import READ_TIMEOUT_S
from ros2probe.backends.host import HostShell
from ros2probe.targets.profile import TargetProfile

HARDWARE_KEY_SCHEMES = ("pkcs11:", "tpm:", "tpm2:")


def _timedatectl_values(lines: list[str]) -> dict[str, str]:
    """The `key=value` pairs `timedatectl show` prints."""
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


@leaf("B.2.1")
@pytest.mark.host
def test_enclave_private_keys_are_not_readable_by_the_current_account(
    host: HostShell, profile: TargetProfile,
) -> None:
    """The account this suite runs as on the host must not be able to read any enclave private key."""
    keystore_path = profile.robot.keystore
    if not keystore_path:
        pytest.skip("no robot.keystore")

    listing = host.run("find", keystore_path, "-name", "key.pem", "-type", "f")
    if not listing.ran:
        pytest.skip(f"undecided: {listing.error}")
    keys = [line.strip() for line in listing.lines]
    if not keys:
        # A keystore the account cannot list hides its keys, it does not lack them.
        pytest.skip("no key.pem" if listing.ok else f"undecided: {listing}")

    # As the login account, never through ssh.sudo: root reads every key.
    readable: list[str] = []
    for key in keys:
        if host.run("test", "-r", key, elevate=False).ok:
            mode = host.stat_path(key)
            readable.append(f"{key} {mode.mode} {mode.owner}")

    assert not readable, f"readable as '{host.whoami(elevate=False)}':\n" + "\n".join(readable)


@leaf("B.2.2")
@pytest.mark.host
def test_security_environment_cannot_be_flipped_by_the_ros_account(
    host: HostShell, profile: TargetProfile,
) -> None:
    """Nothing the ROS account can write may set ROS_SECURITY_ENABLE or ROS_SECURITY_STRATEGY."""
    ros_user = host.ros_process_owner() or profile.robot.ros_user
    home = f"/home/{ros_user}"
    candidates = [
        f"{home}/.bashrc",
        f"{home}/.profile",
        f"{home}/.bash_profile",
        "/etc/environment",
        f"{profile.robot.workspace}/install/setup.bash" if profile.robot.workspace else "",
    ]

    findings: list[str] = []
    checked = False
    for path in [p for p in candidates if p]:
        mode = host.stat_path(path)
        if not mode.exists:
            continue
        checked = True
        mentions = [
            line.strip() for line in host.read_file(path).lines
            if "ROS_SECURITY_" in line and not line.strip().startswith("#")
        ]
        if mentions and mode.writable_by(ros_user):
            findings.append(f"{path} {mode.mode} {mode.owner}: {'; '.join(mentions)}")

    if not checked:
        pytest.skip("no environment file")

    assert not findings, f"writable by '{ros_user}':\n" + "\n".join(findings)


@leaf("B.2.3")
@pytest.mark.host
def test_policy_documents_cannot_be_replaced(
    host: HostShell, profile: TargetProfile,
) -> None:
    """Policy documents must not be writable by the ROS account, and the CA key must not be on the host."""
    keystore_path = profile.robot.keystore
    if not keystore_path:
        pytest.skip("no robot.keystore")
    ros_user = host.ros_process_owner() or profile.robot.ros_user

    docs = host.run(
        "find", keystore_path, "-name", "governance.p7s", "-o",
        "-name", "permissions.p7s",
    )
    ca_keys = host.run("find", f"{keystore_path}/private", "-name", "*.pem")
    if not docs.ran:
        pytest.skip(f"undecided: {docs.error}")

    writable: list[str] = []
    for path in [line.strip() for line in docs.lines]:
        mode = host.stat_path(path)
        if mode.exists and mode.writable_by(ros_user):
            writable.append(f"{path} {mode.mode} {mode.owner}")

    assert not writable, f"writable by '{ros_user}':\n" + "\n".join(writable)
    assert not (ca_keys.ran and ca_keys.lines), f"{ca_keys}"


@leaf("B.2.4")
@pytest.mark.dds
def test_safety_parameters_cannot_be_read_over_the_parameter_service(
    dds: DdsClient, profile: TargetProfile,
) -> None:
    """Safety-relevant parameters must not be reachable over the parameter service by an unauthenticated participant."""
    params = profile.ros.params
    if not params:
        pytest.skip("no ros.params")
    target_node = params[0].node
    names = tuple(p.name for p in profile.ros.params_for(target_node))

    result = dds.anonymous.params(target_node, names, timeout_s=READ_TIMEOUT_S)
    if result.refused_by_router:
        return
    if not result.participant_created:
        pytest.skip(f"undecided: {result.error}")

    assert not result.params_read, "\n".join(
        f"{item.name} = {item.value}" for item in result.params_read
    )
    assert not result.params_listed, \
        f"{target_node} lists: {', '.join(result.params_listed)}"


@leaf("B.2.5")
@pytest.mark.host
def test_time_source_is_authenticated(host: HostShell) -> None:
    """The host clock must come from an authenticated time source."""
    status = host.run("timedatectl", "show")
    if not status.ran:
        pytest.skip(f"undecided: {status.error}")

    values = _timedatectl_values(status.lines)
    ntp_enabled = values.get("NTP", "no") == "yes"
    synced = values.get("NTPSynchronized", "no") == "yes"

    chrony = host.run("systemctl", "is-active", "chrony")
    chrony_conf = host.read_file("/etc/chrony/chrony.conf")
    nts_configured = chrony_conf.ok and "nts" in chrony_conf.stdout.lower()

    assert ntp_enabled and synced, f"{status}"
    assert nts_configured, f"no nts in /etc/chrony/chrony.conf\n{chrony}"


@leaf("B.2.6")
@pytest.mark.host
def test_shared_memory_segments_are_not_world_accessible(
    host: HostShell, profile: TargetProfile,
) -> None:
    """DDS shared-memory segments in /dev/shm must not be readable or writable by other accounts."""
    listing = host.run("ls", "-l", "/dev/shm")
    if not listing.ran:
        pytest.skip(f"undecided: {listing.error}")
    markers: tuple[str, ...]
    if is_zenoh(profile.ros.rmw):
        vendor, markers = "Zenoh", (".zenoh",)
    elif is_cyclone(profile.ros.rmw):
        vendor, markers = "Iceoryx", ("iceoryx", "iox")
    else:
        vendor, markers = "Fast DDS", ("fastrtps", "fast_dds", "fastdds")
    lines = [line for line in listing.lines
             if any(marker in line.lower() for marker in markers)]
    if not lines:
        pytest.skip(f"no {vendor} SHM segments")

    exposed: list[str] = []
    for line in lines:
        perms = line.split()[0] if line.split() else ""
        others = perms[7:10]
        if "r" in others or "w" in others:
            exposed.append(line.strip())

    assert not exposed, "\n".join(exposed)


@leaf("B.2.7")
@pytest.mark.host
def test_host_auditing_and_remote_logging_are_active(host: HostShell) -> None:
    """auditd must be running and logs must be shipped off the robot."""
    auditd = host.run("systemctl", "is-active", "auditd")
    rsyslog = host.run("systemctl", "is-active", "rsyslog")
    journal_conf = host.read_file("/etc/systemd/journald.conf")
    rsyslog_conf = host.run("find", "/etc/rsyslog.d", "-name", "*.conf")
    if not auditd.ran and not rsyslog.ran:
        pytest.skip(f"undecided: {auditd.error}")

    remote_shipping = False
    for path in [line.strip() for line in rsyslog_conf.lines]:
        content = host.read_file(path)
        if content.ok and ("@@" in content.stdout or "omfwd" in content.stdout):
            remote_shipping = True
            break
    if journal_conf.ok and "ForwardToSyslog=yes" in journal_conf.stdout:
        remote_shipping = True

    assert auditd.out.strip() == "active", f"{auditd}"
    assert remote_shipping, f"no remote log forwarding\n{rsyslog_conf}"
