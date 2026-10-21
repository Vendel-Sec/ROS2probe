import datetime as dt

import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import Keystore, Permissions
from ros2probe.backends.artefacts.keystore import RCL_TOPICS
from ros2probe.backends.artefacts.permissions import parse_permissions
from ros2probe.backends.dds import DdsClient
from ros2probe.backends.dds.session import READ_TIMEOUT_S
from ros2probe.targets.profile import TargetProfile

MAX_PERMISSIONS_DAYS = 730


@leaf("A.3.17")
@pytest.mark.static
def test_permissions_documents_are_signed_and_verify(
    permissions: tuple[Permissions, ...],
) -> None:
    """Every permissions.p7s must carry a signature that verifies against the Permissions CA."""
    untrusted = [
        f"{d.path}: present={d.signature.present} verified={d.signature.verified} {d.signature.detail}"
        for d in permissions if not d.signature.trustworthy
    ]
    assert not untrusted, "\n".join(untrusted)


@leaf("A.3.10")
@pytest.mark.static
def test_no_grant_allows_wildcard_topics(permissions: tuple[Permissions, ...]) -> None:
    """No allow_rule may use `*` in its publish or subscribe topic list."""
    offenders = [
        f"{document.path.parent.name}/{grant.name}: {criteria.verb} {', '.join(criteria.topics)}"
        for document in permissions
        for grant in document.grants
        for rule in grant.allow_rules
        for criteria in rule.criteria
        if criteria.has_wildcard
    ]
    assert not offenders, "\n".join(offenders)


@leaf("A.3.11")
@pytest.mark.static
def test_every_grant_defaults_to_deny(permissions: tuple[Permissions, ...]) -> None:
    """Every grant's `<default>` must be DENY."""
    offenders = [
        f"{document.path.parent.name}/{grant.name}: default {grant.default or '<absent>'}"
        for document in permissions
        for grant in document.grants
        if grant.effective_default != "DENY"
    ]
    assert not offenders, "\n".join(offenders)


@leaf("A.3.12")
@pytest.mark.static
def test_grant_validity_is_bounded(
    permissions: tuple[Permissions, ...],
) -> None:
    """Every grant's `<validity>` must be bounded and within the configured maximum."""
    now = dt.datetime.now(dt.UTC)
    unbounded: list[str] = []
    too_long: list[str] = []

    for document in permissions:
        for grant in document.grants:
            name = f"{document.path.parent.name}/{grant.name}"
            not_after = grant.validity.not_after
            if not_after is None:
                unbounded.append(name)
            elif (remaining := (not_after - now).days) > MAX_PERMISSIONS_DAYS:
                too_long.append(f"{name}: {remaining} days left")

    assert not unbounded, "no not_after:\n" + "\n".join(unbounded)
    assert not too_long, f"over {MAX_PERMISSIONS_DAYS} days:\n" + "\n".join(too_long)


@leaf("A.3.13")
@pytest.mark.static
def test_subject_names_are_specific_and_enclaves_are_not_shared(
    keystore: Keystore, permissions: tuple[Permissions, ...],
) -> None:
    """Each grant must name a specific subject DN, and the robot must have more than one enclave."""
    wildcards = [
        f"{document.path.parent.name}/{grant.name}: subject_name {grant.subject_name or '<absent>'!r}"
        for document in permissions
        for grant in document.grants
        if grant.subject_is_wildcard
    ]
    enclaves = keystore.enclaves

    assert not wildcards, "\n".join(wildcards)
    assert len(enclaves) > 1, f"{len(enclaves)} enclave: {', '.join(e.name for e in enclaves) or 'none'}"


@leaf("A.3.14")
@pytest.mark.static
def test_no_unnecessary_relay_grants(permissions: tuple[Permissions, ...]) -> None:
    """No grant may include a `<relay>` rule unless the participant genuinely relays."""
    offenders = [
        f"{document.path.parent.name}/{grant.name}: relays {', '.join(relay.topics) or '<no topics>'}"
        for document in permissions
        for grant in document.grants
        for rule in grant.allow_rules
        if (relay := rule.by_verb("relay")) is not None
    ]
    assert not offenders, "\n".join(offenders)


@leaf("A.3.15")
@pytest.mark.static
def test_permissions_ca_is_distinct_and_its_key_is_absent(
    keystore: Keystore,
) -> None:
    """The Permissions CA must differ from the Identity CA, and no CA private key may be on the robot."""
    identity = keystore.identity_ca
    perms = keystore.permissions_ca
    if identity is None or perms is None:
        pytest.skip("CA certificates unreadable")

    keys_present = [f.path.name for f in keystore.ca_private_keys if f.exists]

    assert not keystore.identity_and_permissions_ca_are_same, f"one CA for both roles: {identity.subject}"
    assert not keys_present, f"{keystore.private_dir.path}: {', '.join(keys_present)}"


@leaf("A.3.10")
@pytest.mark.dds
def test_low_privilege_credential_cannot_read_outside_its_grant(
    dds: DdsClient, profile: TargetProfile,
) -> None:
    """A sensor-driver credential must not receive messages on a topic outside its grant."""
    session = dds.credentialed
    held = profile.credentials
    if not session.available or held is None:
        pytest.skip("no credentials")
    grant = parse_permissions(
        held.keystore / "enclaves" / held.enclave.strip("/") / "permissions.xml", None,
    )
    if grant is None:
        pytest.skip(f"no permissions.xml for {held.enclave}")
    graph = dds.credentialed_graph()
    if not graph.participant_created:
        pytest.skip(f"undecided: {graph.error}")
    outside = [t for t in dds.credentialed_topics() if t.type and not grant.grants_topic(t.dds_name)
               and t.dds_name not in RCL_TOPICS]
    if not outside:
        pytest.skip("no topic outside the grant")
    topic = outside[0]

    result = session.read(topic.name, topic.type, timeout_s=READ_TIMEOUT_S)
    if result.refused_by_router:
        pytest.skip(f"undecided: {result.router_detail}")
    if not result.participant_created:
        pytest.skip(f"undecided: {result.error}")

    assert result.messages_received == 0, \
        f"{session.enclave} received {result.messages_received} on {topic.name}: {result.first_message[:200]}"
