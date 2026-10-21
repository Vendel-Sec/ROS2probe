import pytest

from ros2probe.attacktree.leaf import leaf
from ros2probe.backends.artefacts import Enclave, Keystore
from ros2probe.backends.artefacts.rmw_config import EXPECTED_AUTH_PLUGIN, Family
from ros2probe.backends.dds.zenoh_router import RouterProbe, RouterTransport
from ros2probe.targets.profile import TargetProfile

MAX_CERT_DAYS = 365
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256


def _shared(enclaves: tuple[Enclave, ...], attribute: str) -> list[list[str]]:
    """Enclave names that share one certificate attribute, one list per value."""
    groups: dict[str, list[str]] = {}
    for enclave in enclaves:
        if enclave.certificate is not None:
            groups.setdefault(getattr(enclave.certificate, attribute), []).append(enclave.name)
    return [names for names in groups.values() if len(names) > 1]


@leaf("A.1.1")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_auth_plugin_is_pki_dh(keystore: Keystore) -> None:
    """dds.sec.auth.plugin must be builtin.PKI-DH."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")

    assert profile.auth_plugin == EXPECTED_AUTH_PLUGIN, \
        f"{profile.path}: {profile.names.auth_plugin} = {profile.auth_plugin or '<absent>'}"


@leaf("A.1.1")
@pytest.mark.static
@pytest.mark.rmw(Family.ZENOH)
def test_zenoh_configs_demand_a_client_certificate(keystore: Keystore) -> None:
    """Every Zenoh router and session config must set enable_mtls and listen on TLS only."""
    configs = keystore.all_zenoh_configs
    assert configs, f"no Zenoh config under {keystore.root}"

    unparsable = [f"{c.path}: {c.parse_error}" for c in configs if c.parse_error]
    plaintext = [f"{c.path}: {', '.join(c.exposed_plaintext_listeners)}" for c in configs
                 if c.exposed_plaintext_listeners]
    no_mtls = [f"{c.path}: transport.link.tls.enable_mtls = {c.tls_enable_mtls}" for c in configs
               if c.tls_enable_mtls is not True]

    assert not unparsable, "unparsable:\n" + "\n".join(unparsable)
    assert not plaintext, "plaintext listeners:\n" + "\n".join(plaintext)
    assert not no_mtls, "\n".join(no_mtls)


@leaf("A.1.1")
@pytest.mark.dds
@pytest.mark.rmw(Family.ZENOH)
def test_zenoh_router_demands_a_client_certificate(
    profile: TargetProfile, zenoh_router: RouterProbe,
) -> None:
    """The live router must refuse a TLS client that shows no certificate."""
    router, found = profile.zenoh_router, zenoh_router
    assert found.transport is RouterTransport.MTLS, f"router {router} is {found.transport}: {found.detail}"


@leaf("A.1.3")
@pytest.mark.static
def test_each_enclave_has_a_distinct_identity(keystore: Keystore) -> None:
    """Each enclave must hold its own certificate with its own subject DN."""
    enclaves = tuple(e for e in keystore.enclaves if e.certificate is not None)
    if len(enclaves) < 2:
        pytest.skip(f"{len(enclaves)} enclave with a certificate, nothing to compare")

    shared_fingerprint = _shared(enclaves, "fingerprint")
    shared_subject = _shared(enclaves, "subject")
    assert not shared_fingerprint, f"same certificate: {shared_fingerprint}"
    assert not shared_subject, f"same subject DN: {shared_subject}"


@leaf("A.1.4")
@pytest.mark.static
def test_private_keys_are_not_group_or_world_readable(keystore: Keystore) -> None:
    """Private key files must be 0400, or 0440 at the widest."""
    keys = tuple(e for e in keystore.enclaves if e.key.exists)
    if not keys:
        pytest.skip("no key.pem")

    exposed = [
        f"{e.name}/key.pem {e.key.mode_octal}" for e in keys
        if e.key.group_or_world_readable or e.key.group_or_world_writable
    ]
    assert not exposed, "\n".join(exposed)


@leaf("A.1.5")
@pytest.mark.static
def test_private_keys_are_encrypted_and_passphrase_is_not_stored_with_them(keystore: Keystore) -> None:
    """Private keys must be encrypted, with no key.pass beside them and no passphrase in the rmw profile."""
    enclaves = tuple(e for e in keystore.enclaves if e.key.exists)
    if not enclaves:
        pytest.skip("no key.pem")

    beside = [e.name for e in enclaves if e.passphrase_is_leaked_beside_key]
    in_xml = [e.name for e in enclaves if e.profile is not None and e.profile.key_password]
    unreadable = [e.name for e in enclaves if e.key_encrypted is None]
    unencrypted = [e.name for e in enclaves if e.key_encrypted is False]

    assert not beside, f"passphrase file beside key: {', '.join(beside)}"
    assert not in_xml, f"passphrase in XML profile: {', '.join(in_xml)}"
    assert not unencrypted, f"unencrypted key: {', '.join(unencrypted)}"
    if unreadable:
        pytest.skip(f"key.pem unreadable: {', '.join(unreadable)}")


@leaf("A.1.6")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS, Family.CYCLONE)
def test_identity_crl_is_configured(keystore: Keystore) -> None:
    """identity_crl must be configured."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")

    assert profile.identity_crl, f"{profile.path}: {profile.names.identity_crl} absent"


@leaf("A.1.7")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS)
def test_key_agreement_is_not_pinned_to_legacy_dh(keystore: Keystore) -> None:
    """preferred_key_agreement must be AUTO or an approved ECDH suite."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")
    if not profile.names.key_agreement:
        pytest.skip(f"{profile.vendor} has no key agreement setting")

    assert profile.key_agreement_is_acceptable, \
        f"{profile.path}: {profile.names.key_agreement} = {profile.key_agreement}"


@leaf("A.1.8")
@pytest.mark.static
@pytest.mark.rmw(Family.FASTDDS)
def test_legacy_algorithm_advertisement_is_off(keystore: Keystore) -> None:
    """transmit_algorithms_as_legacy must be false."""
    profile = keystore.any_profile
    if profile is None:
        pytest.skip(f"no rmw profile in {keystore.root}")
    if not profile.names.legacy_algorithms:
        pytest.skip(f"{profile.vendor} has no legacy algorithm setting")

    assert not profile.advertises_legacy_algorithms, \
        f"{profile.path}: {profile.names.legacy_algorithms} = {profile.legacy_algorithms}"


@leaf("A.1.9")
@pytest.mark.static
def test_certificate_lifetimes_are_bounded(keystore: Keystore) -> None:
    """Certificates must be valid and live at most MAX_CERT_DAYS."""
    certs = keystore.all_certificates
    if not certs:
        pytest.skip("no certificate")

    expired = [f"{name}: expired {-cert.remaining_days} days ago" for name, cert in certs if cert.expired]
    too_long = [f"{name}: {cert.lifetime_days} days" for name, cert in certs
                if cert.lifetime_days > MAX_CERT_DAYS]

    assert not expired, "\n".join(expired)
    assert not too_long, f"lifetime over {MAX_CERT_DAYS} days:\n" + "\n".join(too_long)


@leaf("A.1.10")
@pytest.mark.static
def test_identity_keys_meet_the_minimum_size(keystore: Keystore) -> None:
    """RSA keys must be at least 2048 bits and EC curves at least P-256."""
    certs = keystore.all_certificates
    if not certs:
        pytest.skip("no certificate")

    weak = [f"{name}: {cert.strength_summary}" for name, cert in certs
            if not cert.meets_minimum(MIN_RSA_BITS, MIN_EC_BITS)]
    assert not weak, "\n".join(weak)
