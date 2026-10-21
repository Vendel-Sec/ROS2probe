import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import BaseKind, Governance, Keystore
from ros2probe.backends.artefacts.rmw_config import EXPECTED_CRYPTO_PLUGIN, Family
from ros2probe.backends.wire import Capture
from ros2probe.targets.profile import TargetProfile


def _rule_lines(resolved, attribute: str) -> list[str]:
    return [
        f"{expression}: rule #{rule.index} '{rule.topic_expression}' {attribute} = {getattr(rule, attribute)}"
        for expression, rule in resolved
    ]


def _skip_unless_judgeable(capture: Capture) -> None:
    if capture.error:
        pytest.skip(f"undecided: {capture.error}")
    if not capture.usable:
        pytest.skip("undecided: no RTPS captured")
    if not capture.carries_samples:
        pytest.skip("undecided: no DATA captured")


@leaf("A.2.1")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_crypto_plugin_is_aes_gcm_gmac(keystore: Keystore) -> None:
    """dds.sec.crypto.plugin must be builtin.AES-GCM-GMAC."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")

    assert profile.crypto_plugin == EXPECTED_CRYPTO_PLUGIN, \
        f"{profile.path}: {profile.names.crypto_plugin} = {profile.crypto_plugin or '<absent>'}"


@leaf("A.2.2")
@pytest.mark.static
def test_rtps_protection_is_encrypt(governance: Governance) -> None:
    """rtps_protection_kind must be ENCRYPT."""
    kind = governance.domain_rule.rtps_protection_kind
    assert kind.protects_confidentiality, f"{governance.path}: rtps_protection_kind = {kind}"


@leaf("A.2.3")
@pytest.mark.static
def test_discovery_protection_is_encrypt(governance: Governance) -> None:
    """discovery_protection_kind must be ENCRYPT."""
    kind = governance.domain_rule.discovery_protection_kind
    assert kind.protects_confidentiality, f"{governance.path}: discovery_protection_kind = {kind}"


@leaf("A.2.4")
@pytest.mark.static
def test_liveliness_protection_is_encrypt(governance: Governance) -> None:
    """liveliness_protection_kind must be ENCRYPT."""
    kind = governance.domain_rule.liveliness_protection_kind
    assert kind.protects_integrity, f"{governance.path}: liveliness_protection_kind = {kind}"


@leaf("A.2.5")
@pytest.mark.static
def test_metadata_protection_is_set_on_safety_topics(
    governance: Governance, granted_topics: tuple[str, ...],
) -> None:
    """metadata_protection_kind must not be NONE on any application topic."""
    if not granted_topics:
        pytest.skip("no granted topics")
    resolved = governance.resolve(granted_topics)
    if not resolved:
        pytest.skip("no matching topic rule")

    unprotected = [(e, r) for e, r in resolved if r.metadata_protection_kind.base is BaseKind.NONE]
    assert not unprotected, "\n".join(_rule_lines(unprotected, "metadata_protection_kind"))


@leaf("A.2.6")
@pytest.mark.static
def test_data_protection_is_not_none_on_safety_topics(
    governance: Governance, granted_topics: tuple[str, ...],
) -> None:
    """data_protection_kind must not be NONE on any application topic."""
    if not granted_topics:
        pytest.skip("no granted topics")
    resolved = governance.resolve(granted_topics)
    if not resolved:
        pytest.skip("no matching topic rule")

    unprotected = [(e, r) for e, r in resolved if r.data_protection_kind.base is BaseKind.NONE]
    assert not unprotected, "\n".join(_rule_lines(unprotected, "data_protection_kind"))


@leaf("A.2.7")
@pytest.mark.static
def test_confidential_topics_use_encrypt_not_sign(
    governance: Governance, granted_topics: tuple[str, ...],
) -> None:
    """Application topics must use ENCRYPT, not SIGN."""
    if not granted_topics:
        pytest.skip("no granted topics")
    resolved = governance.resolve(granted_topics)
    if not resolved:
        pytest.skip("no matching topic rule")

    signed_only = [(e, r) for e, r in resolved if r.data_protection_kind.base is BaseKind.SIGN]
    assert not signed_only, "\n".join(_rule_lines(signed_only, "data_protection_kind"))


@leaf("A.2.8")
@pytest.mark.static
def test_actuation_topics_use_origin_authentication(
    governance: Governance, profile: TargetProfile,
) -> None:
    """Actuation topics must use an origin-authentication protection variant."""
    expressions = tuple(t.dds_name for t in profile.ros.actuation_topics)
    if not expressions:
        pytest.skip("no ros.actuation")
    resolved = governance.resolve(expressions)
    if not resolved:
        pytest.skip("no matching topic rule")

    rtps_kind = governance.domain_rule.rtps_protection_kind
    missing = [(e, r) for e, r in resolved if not r.metadata_protection_kind.origin_authentication]

    assert rtps_kind.origin_authentication, f"{governance.path}: rtps_protection_kind = {rtps_kind}"
    assert not missing, "\n".join(_rule_lines(missing, "metadata_protection_kind"))


@leaf("A.2.2")
@pytest.mark.wire
def test_no_plaintext_rtps_on_the_segment(capture: Capture) -> None:
    """No RTPS datagram on the segment may carry an unprotected DATA submessage."""
    _skip_unless_judgeable(capture)

    plaintext = capture.plaintext_packets
    assert not plaintext, f"{len(plaintext)} plaintext DATA datagram(s):\n{capture.sample(plaintext)}"


@leaf("A.2.3")
@pytest.mark.wire
def test_discovery_does_not_leak_topic_and_type_names(capture: Capture) -> None:
    """A capture must carry no readable ROS names, and no clear-text SPDP discovery."""
    if capture.error:
        pytest.skip(f"undecided: {capture.error}")
    if not capture.usable:
        pytest.skip("undecided: no RTPS captured")

    leaking = capture.name_leaking_packets
    assert not leaking, f"{len(leaking)} datagram(s) leak names:\n" + "\n".join(capture.leaked_names())

    spdp = capture.spdp_only_packets
    assert not spdp, f"low: {len(spdp)} SPDP packets in clear: {', '.join(capture.spdp_exposure())}"
