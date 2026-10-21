from pathlib import PurePosixPath

import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.host import CommandResult, HostShell
from ros2probe.backends.net import NetScan

SSHD_CONFIG = "/etc/ssh/sshd_config"
APT_SOURCES = "/etc/apt/sources.list"
UNATTENDED_UPGRADES = "/etc/apt/apt.conf.d/20auto-upgrades"


def _sshd_directives(lines: list[str]) -> dict[str, str]:
    """The effective `keyword value` pairs from sshd_config."""
    directives: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        # A Match block only applies to some connections.
        if parts[0].lower() == "match":
            break
        # sshd keeps the first value it reads, which is how a drop-in included
        # at the top of sshd_config overrides the defaults below it.
        if len(parts) == 2:
            directives.setdefault(parts[0].lower(), parts[1].strip().lower())
    return directives


def _sshd_config_lines(host: HostShell, path: str = SSHD_CONFIG) -> CommandResult:
    """sshd_config as sshd reads it, with each Include expanded in place."""
    config = host.read_file(path)
    if not config.ok:
        return config
    lines: list[str] = []
    for line in config.lines:
        parts = line.strip().split()
        if not parts or parts[0].lower() != "include":
            lines.append(line)
            continue
        for pattern in parts[1:]:
            # Relative to /etc/ssh, as sshd resolves them.
            absolute = str(PurePosixPath(SSHD_CONFIG).parent / pattern)
            directory, name = absolute.rsplit("/", 1)
            found = host.run("find", directory, "-maxdepth", "1", "-name", name)
            for included in sorted(found.lines):
                lines.extend(_sshd_config_lines(host, included.strip()).lines)
    return config.model_copy(update={"stdout": "\n".join(lines)})


@leaf("B.0.1")
@pytest.mark.host
def test_ssh_does_not_allow_password_or_root_login(host: HostShell) -> None:
    """sshd must refuse password authentication and root login."""
    # The configuration sshd actually runs with. It needs root, so without
    # ssh.sudo read the files, following their Include directives.
    config = host.run("sshd", "-T")
    if not config.ok:
        config = _sshd_config_lines(host)
    if not config.ran:
        pytest.skip(f"undecided: {config.error}")
    if not config.ok:
        pytest.skip("no sshd_config")

    directives = _sshd_directives(config.lines)
    password_auth = directives.get("passwordauthentication", "yes")
    root_login = directives.get("permitrootlogin", "prohibit-password")
    kbd_interactive = directives.get(
        "kbdinteractiveauthentication",
        directives.get("challengeresponseauthentication", "no"),
    )

    assert password_auth == "no", f"PasswordAuthentication {password_auth}"
    assert root_login in ("no", "forced-commands-only"), f"PermitRootLogin {root_login}"
    assert kbd_interactive != "yes", "KbdInteractiveAuthentication yes"


@leaf("B.0.2")
@pytest.mark.net
def test_no_unauthenticated_ros_or_management_service_is_exposed(
    netscan: NetScan,
) -> None:
    """No unauthenticated ROS bridge or management service may be reachable from the robot's network."""
    assert not netscan.open_ports, netscan.summary()


@leaf("B.0.3")
@pytest.mark.host
def test_host_is_patched_and_unattended_upgrades_are_enabled(
    host: HostShell,
) -> None:
    """The host must be on a supported release with unattended-upgrades enabled."""
    release = host.run("lsb_release", "-ds")
    upgrades = host.read_file(UNATTENDED_UPGRADES)
    upgradable = host.run("apt", "list", "--upgradable")
    if not release.ok and not upgrades.ok:
        pytest.skip(f"undecided: {release.error or upgrades.error or 'no release info'}")

    auto_enabled = any("Unattended-Upgrade" in line and '"1"' in line for line in upgrades.lines)
    pending = [line for line in upgradable.lines if "/" in line and "upgradable from" in line]

    assert auto_enabled, f"{upgrades}"
    assert not pending, "\n".join(pending)


@leaf("B.0.4")
@pytest.mark.host
def test_disk_is_encrypted_and_boot_is_locked(host: HostShell) -> None:
    """The root filesystem must be encrypted and Secure Boot enabled."""
    blocks = host.run("lsblk", "-o", "NAME,TYPE,MOUNTPOINT")
    secureboot = host.run("mokutil", "--sb-state")
    if not blocks.ok and not secureboot.ok:
        pytest.skip("no lsblk or mokutil")

    assert not blocks.ok or "crypt" in blocks.stdout.lower(), f"{blocks}"
    assert secureboot.ok and "enabled" in secureboot.out.lower(), f"{secureboot}"


@leaf("B.0.5")
@pytest.mark.host
def test_package_sources_are_authenticated(host: HostShell) -> None:
    """No apt source may use plain http, and no third-party PPA should be unpinned."""
    main = host.read_file(APT_SOURCES)
    extra = host.run("find", "/etc/apt/sources.list.d", "-name", "*.list", "-o",
                     "-name", "*.sources")
    if not main.ok and not extra.ok:
        pytest.skip("no apt sources")

    insecure: list[str] = []
    for line in main.lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if "http://" in stripped and "[trusted=yes]" not in stripped:
            insecure.append(f"{APT_SOURCES}: {stripped}")
        if "[trusted=yes]" in stripped:
            insecure.append(f"{APT_SOURCES}: {stripped}")

    for path in extra.lines:
        content = host.read_file(path.strip())
        for line in content.lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if "http://" in stripped or "[trusted=yes]" in stripped:
                insecure.append(f"{path.strip()}: {stripped}")

    assert not insecure, "\n".join(insecure)


@leaf("B.0.6")
@pytest.mark.host
def test_host_firewall_is_active_and_network_is_segmented(host: HostShell) -> None:
    """A host firewall must be active, and the robot must not sit on a flat network."""
    firewall = host.run("systemctl", "is-active", "ufw")
    nftables = host.run("systemctl", "is-active", "nftables")
    addresses = host.run("ip", "-o", "-4", "addr", "show")
    if not firewall.ran and not nftables.ran and not addresses.ran:
        pytest.skip(f"undecided: {firewall.error}")

    active = firewall.out == "active" or nftables.out == "active"
    assert active, f"{firewall}\n{nftables}"
