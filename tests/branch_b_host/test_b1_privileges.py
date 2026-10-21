import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.host import HostShell
from ros2probe.targets.profile import TargetProfile

DANGEROUS_GROUPS = frozenset({"docker", "lxd", "sudo", "adm", "disk", "shadow"})

DANGEROUS_CAPS = ("cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
                  "cap_sys_module", "cap_setuid", "cap_setgid")

LOGIN_SHELLS = ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                "/usr/bin/zsh", "/bin/dash")


@leaf("B.1.0")
@pytest.mark.host
def test_ros_does_not_run_as_a_login_account(host: HostShell) -> None:
    """The account running ROS must not be an account an attacker can log in to."""
    owner = host.ros_process_owner()
    if not owner:
        pytest.skip("no ROS process")

    passwd = host.run("getent", "passwd", owner)
    account_shell = passwd.out.rsplit(":", 1)[-1] if passwd.ok else "unknown"
    privileged = sorted(set(host.groups_of(owner)) & DANGEROUS_GROUPS)

    assert account_shell not in LOGIN_SHELLS, f"{passwd}"
    assert not privileged, f"'{owner}' in {', '.join(privileged)}"


@leaf("B.1.1")
@pytest.mark.host
def test_ros_account_has_no_path_to_root(
    host: HostShell, profile: TargetProfile,
) -> None:
    """The ROS account must not be in the docker group, nor hold passwordless sudo."""
    ros_user = host.ros_process_owner() or profile.robot.ros_user
    groups = host.groups_of(ros_user)
    sudo = host.run("sudo", "-n", "-l", "-U", ros_user)
    if not groups and not sudo.ran:
        pytest.skip(f"undecided: {sudo.error}")

    root_groups = sorted({"docker", "lxd"} & set(groups))
    assert not root_groups, f"'{ros_user}' in {', '.join(root_groups)}"
    assert not (sudo.ok and "NOPASSWD" in sudo.stdout), f"{sudo}"


@leaf("B.1.2")
@pytest.mark.host
def test_systemd_unit_and_environment_file_are_not_writable(
    host: HostShell, profile: TargetProfile,
) -> None:
    """The unit that launches ROS, and any EnvironmentFile it reads, must not be writable by the ROS account."""
    unit_name = profile.robot.unit
    if not unit_name:
        pytest.skip("robot.unit not set")
    ros_user = host.ros_process_owner() or profile.robot.ros_user

    location = host.run("systemctl", "show", "-p", "FragmentPath",
                        "-p", "EnvironmentFiles", unit_name)
    if not location.ok:
        pytest.skip(f"undecided: {location.error or f'exit {location.exit_code}'}")

    paths: list[str] = []
    for line in location.lines:
        key, _, value = line.partition("=")
        if key == "FragmentPath" and value:
            paths.append(value)
        elif key == "EnvironmentFiles" and value:
            paths.append(value.split(" ", 1)[0])

    modes = [mode for mode in map(host.stat_path, paths) if mode.exists]
    if not modes:
        pytest.skip(f"no files for unit {unit_name}")

    writable = [f"{m.path} {m.mode} {m.owner}:{m.group}" for m in modes
                if m.writable_by(ros_user)]
    assert not writable, f"writable by '{ros_user}':\n" + "\n".join(writable)


@leaf("B.1.3")
@pytest.mark.host
def test_workspace_is_not_writable_by_unprivileged_users(
    host: HostShell, profile: TargetProfile,
) -> None:
    """The colcon workspace, and `install/setup.bash` in particular, must not be writable by unprivileged users."""
    workspace = profile.robot.workspace
    if not workspace:
        pytest.skip("no robot.workspace")

    candidates = [
        workspace,
        f"{workspace}/install",
        f"{workspace}/install/setup.bash",
        f"{workspace}/install/local_setup.bash",
    ]
    modes = [mode for mode in map(host.stat_path, candidates) if mode.exists]
    if not modes:
        pytest.skip(f"no {workspace} on target")

    writable = [
        f"{m.path} {m.mode} {m.owner}:{m.group}" for m in modes
        if m.world_writable or (m.group_writable and m.group not in ("root",))
    ]
    assert not writable, "\n".join(writable)


@leaf("B.1.4")
@pytest.mark.host
def test_running_kernel_matches_the_installed_kernel(host: HostShell) -> None:
    """The running kernel must be the newest installed one."""
    running = host.run("uname", "-r")
    installed = host.run("dpkg", "--list", "linux-image-*")
    if not running.ok:
        pytest.skip(f"undecided: {running}")
    if not installed.ok:
        pytest.skip(f"undecided: {installed}")

    current = running.out.strip()
    versions: list[str] = []
    for line in installed.lines:
        if not line.startswith("ii"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("linux-image-"):
            name = fields[1].removeprefix("linux-image-")
            if name and name[0].isdigit():
                versions.append(name)

    newest = sorted(versions)[-1] if versions else ""
    stale = bool(newest) and not current.startswith(newest.split("-generic")[0])

    assert not stale, f"{running}\nnewest installed: {newest}"


@leaf("B.1.5")
@pytest.mark.host
def test_no_unexpected_suid_or_capability_bearing_binaries(
    host: HostShell, profile: TargetProfile,
) -> None:
    """Vendor driver binaries must not be SUID root nor carry dangerous capabilities."""
    search_roots = [profile.robot.workspace or "/opt", "/usr/local"]
    findings: list[str] = []
    searched = False
    error = ""

    for root in search_roots:
        if not root:
            continue
        suid = host.run(
            "find", root, "-maxdepth", "6", "-type", "f", "-perm", "-4000",
        )
        if suid.ran:
            searched = True
            findings.extend(f"SUID: {line.strip()}" for line in suid.lines)
        else:
            error = suid.error

        caps = host.run("getcap", "-r", root)
        if caps.ran:
            findings.extend(
                f"capability: {line.strip()}" for line in caps.lines
                if any(cap in line.lower() for cap in DANGEROUS_CAPS)
            )

    if not searched:
        pytest.skip(f"undecided: {error}")

    assert not findings, "\n".join(findings)
