import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import Governance, Keystore
from ros2probe.backends.artefacts.rmw_config import EXPECTED_ACCESS_PLUGIN, Family
from ros2probe.backends.dds import DdsClient
from ros2probe.backends.dds.session import MATCH_TIMEOUT_S
from ros2probe.targets.profile import TargetProfile

MAX_REASONABLE_DOMAIN_SPAN = 4


def _xml_bool(value: bool | None) -> str:
    return "<absent>" if value is None else str(value).lower()


@leaf("A.3.16")
@pytest.mark.static
def test_governance_document_is_signed_and_verifies(governance: Governance) -> None:
    """governance.p7s must carry an S/MIME signature that verifies against the Permissions CA."""
    signature = governance.signature
    assert signature.trustworthy, f"{governance.path}: {signature.detail}"


@leaf("A.3.1")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_access_control_plugin_is_configured(keystore: Keystore) -> None:
    """dds.sec.access.plugin must be builtin.Access-Permissions."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")

    assert profile.access_plugin == EXPECTED_ACCESS_PLUGIN, \
        f"{profile.path}: {profile.names.access_plugin} = {profile.access_plugin or '<absent>'}"


@leaf("A.3.2")
@pytest.mark.static
def test_unauthenticated_participants_are_not_allowed(governance: Governance) -> None:
    """allow_unauthenticated_participants must be false."""
    value = governance.domain_rule.allow_unauthenticated_participants
    assert value is not True, f"{governance.path}: allow_unauthenticated_participants = {_xml_bool(value)}"


@leaf("A.3.3")
@pytest.mark.static
def test_join_access_control_is_enabled(governance: Governance) -> None:
    """enable_join_access_control must be true."""
    value = governance.domain_rule.enable_join_access_control
    assert value is True, f"{governance.path}: enable_join_access_control = {_xml_bool(value)}"


@leaf("A.3.4")
@pytest.mark.static
def test_read_access_control_is_enabled_on_every_topic_rule(
    governance: Governance,
) -> None:
    """enable_read_access_control must be true in every topic rule."""
    rules = governance.domain_rule.topic_rules
    if not rules:
        pytest.skip("no topic rules")

    disabled = [f"rule #{r.index} '{r.topic_expression}'" for r in rules if r.enable_read_access_control is False]
    assert not disabled, "\n".join(disabled)


@leaf("A.3.5")
@pytest.mark.static
def test_write_access_control_is_enabled_on_every_topic_rule(
    governance: Governance,
) -> None:
    """enable_write_access_control must be true in every topic rule."""
    rules = governance.domain_rule.topic_rules
    if not rules:
        pytest.skip("no topic rules")

    disabled = [f"rule #{r.index} '{r.topic_expression}'" for r in rules if r.enable_write_access_control is False]
    assert not disabled, "\n".join(disabled)


@leaf("A.3.6")
@pytest.mark.static
def test_discovery_protection_is_enabled_on_every_topic_rule(
    governance: Governance,
) -> None:
    """enable_discovery_protection must be true in every topic rule."""
    rules = governance.domain_rule.topic_rules
    if not rules:
        pytest.skip("no topic rules")

    disabled = [f"rule #{r.index} '{r.topic_expression}'" for r in rules if r.enable_discovery_protection is False]
    assert not disabled, "\n".join(disabled)


@leaf("A.3.7")
@pytest.mark.static
def test_liveliness_protection_is_enabled_on_every_topic_rule(
    governance: Governance,
) -> None:
    """enable_liveliness_protection must be true in every topic rule."""
    rules = governance.domain_rule.topic_rules
    if not rules:
        pytest.skip("no topic rules")

    disabled = [f"rule #{r.index} '{r.topic_expression}'" for r in rules if r.enable_liveliness_protection is False]
    assert not disabled, "\n".join(disabled)


@leaf("A.3.8")
@pytest.mark.static
def test_no_permissive_wildcard_rule_shadows_specific_rules(
    governance: Governance,
) -> None:
    """A catch-all topic rule must not be ordered before the specific rules."""
    rules = governance.domain_rule.topic_rules
    if len(rules) < 2:
        pytest.skip("fewer than two topic rules")

    shadowing = [
        f"rule #{r.index} '{r.topic_expression}' shadows {len(rules) - i - 1} rule(s)"
        for i, r in enumerate(rules[:-1]) if r.is_wildcard
    ]
    assert not shadowing, "\n".join(shadowing)


@leaf("A.3.9")
@pytest.mark.static
def test_domain_rule_is_scoped_to_the_operational_domain(
    governance: Governance, profile: TargetProfile,
) -> None:
    """The domain rule must cover the operational domain and few others."""
    rule = governance.domain_rule
    expected = profile.ros.domain
    listed = ", ".join(str(d) for d in rule.domains) or "<none>"

    assert rule.domain_span <= MAX_REASONABLE_DOMAIN_SPAN, \
        f"{governance.path}: <domains> = {listed}, {rule.domain_span} ids"
    if expected is not None and rule.domains:
        assert any(d.low <= expected <= d.high for d in rule.domains), \
            f"{governance.path}: <domains> = {listed}, ros.domain = {expected}"


@leaf("A.3.5")
@pytest.mark.dds
def test_unauthenticated_writer_does_not_match_actuation_subscriber(
    dds: DdsClient, profile: TargetProfile, pytestconfig: pytest.Config,
) -> None:
    """An unauthenticated participant's writer must not match any subscriber on an actuation topic."""
    actuation = profile.ros.actuation_topics
    if not actuation:
        pytest.skip("no ros.actuation")
    topic = actuation[0]
    armed = pytestconfig.getoption("--arm") and pytestconfig.getoption("--allow-actuation-payload")

    result = dds.anonymous.write_match(
        topic.name, topic.type, timeout_s=MATCH_TIMEOUT_S, publish_count=int(armed),
        payload=profile.ros.payloads.get(topic.name) if armed else None,
    )
    if result.refused_by_router:
        return
    if not result.participant_created:
        pytest.skip(f"undecided: {result.error}")

    readers = [f"{i.node_namespace.rstrip('/')}/{i.node_name}" for i in result.subscription_info]
    assert result.matched_subscriptions == 0, \
        f"{topic.name}: matched {result.matched_subscriptions} reader(s)\n" + "\n".join(readers)
