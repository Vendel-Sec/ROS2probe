import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import Keystore
from ros2probe.backends.artefacts.rmw_config import Family
from ros2probe.backends.host import HostShell
from ros2probe.targets.profile import TargetProfile


@leaf("A.4.1")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_xml_profile_is_not_writable(keystore: Keystore) -> None:
    """The rmw profile, Fast DDS XML or Cyclone DDS config, must not be group or world writable."""
    profiles = tuple(item for item in keystore.all_profiles if item.facts.exists)
    if not profiles:
        pytest.skip(f"no rmw profile in {keystore.root}")

    writable = [f"{p.path} {p.facts.mode_octal} uid {p.facts.uid}"
                for p in profiles if p.facts.group_or_world_writable]
    assert not writable, "\n".join(writable)


@leaf("A.4.2")
@pytest.mark.static
def test_keystore_directory_ownership_and_mode(keystore: Keystore) -> None:
    """The keystore directory must not be group or world writable."""
    facts = keystore.facts
    assert not facts.group_or_world_writable, \
        f"{keystore.root} mode {facts.mode_octal} uid {facts.uid} gid {facts.gid}"


@leaf("A.4.3")
@pytest.mark.static
def test_ca_signing_keys_are_absent_from_the_robot(keystore: Keystore) -> None:
    """keystore/private must not exist on a running robot."""
    private = keystore.private_dir
    keys = [f"{f.path} {f.mode_octal}" for f in keystore.ca_private_keys if f.exists]

    assert not (private.exists and keys), "\n".join(keys)


@leaf("A.4.1")
@pytest.mark.host
def test_artefacts_are_not_writable_by_the_ros_account_on_the_host(
    host: HostShell, profile: TargetProfile,
) -> None:
    """On the target host, neither the keystore nor the XML profile may be writable by the ROS account."""
    ros_user = profile.robot.ros_user
    paths = tuple(p for p in (profile.robot.keystore, profile.robot.profile) if p)
    if not paths:
        pytest.skip("no robot.keystore or robot.profile")

    modes = [m for m in (host.stat_path(p) for p in paths) if m.exists]
    if not modes:
        pytest.skip(f"undecided: {', '.join(paths)} absent on host")

    writable = [f"{m.path} {m.mode} {m.owner}:{m.group}" for m in modes if m.writable_by(ros_user)]
    assert not writable, f"writable by {ros_user}:\n" + "\n".join(writable)
