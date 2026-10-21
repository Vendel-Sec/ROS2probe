from pathlib import Path
from xml.etree import ElementTree as ET

from .files import file_facts
from .rmw_config import SettingNames, XmlProfile
from .xml_support import strip_namespaces, text_of

AUTH_PLUGIN = "dds.sec.auth.plugin"
CRYPTO_PLUGIN = "dds.sec.crypto.plugin"
ACCESS_PLUGIN = "dds.sec.access.plugin"

PKI_DH_PREFIX = "dds.sec.auth.builtin.PKI-DH."
IDENTITY_CRL = f"{PKI_DH_PREFIX}identity_crl"
KEY_AGREEMENT = f"{PKI_DH_PREFIX}preferred_key_agreement"
LEGACY_ALGORITHMS = f"{PKI_DH_PREFIX}transmit_algorithms_as_legacy"
KEY_PASSWORD = f"{PKI_DH_PREFIX}password"
PRIVATE_KEY = f"{PKI_DH_PREFIX}private_key"

FASTDDS_NAMES = SettingNames(
    vendor="Fast DDS",
    auth_plugin=AUTH_PLUGIN,
    crypto_plugin=CRYPTO_PLUGIN,
    access_plugin=ACCESS_PLUGIN,
    identity_crl=IDENTITY_CRL,
    key_password=KEY_PASSWORD,
    key_agreement=KEY_AGREEMENT,
    legacy_algorithms=LEGACY_ALGORITHMS,
)


def parse_fastdds_profile(path: Path) -> XmlProfile | None:
    """A Fast DDS XML profile. Security lives in `<property>` name/value pairs."""
    facts = file_facts(path)
    if not facts.exists:
        return None
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError) as exc:
        return XmlProfile(
            path=path, facts=facts, names=FASTDDS_NAMES, parse_error=str(exc),
        )

    strip_namespaces(root)
    properties: dict[str, str] = {}
    for element in root.iter("property"):
        name = text_of(element, "name")
        if name:
            # First one wins, as it did when this was a list searched in order.
            properties.setdefault(name, text_of(element, "value") or "")
    return XmlProfile(
        path=path,
        facts=facts,
        names=FASTDDS_NAMES,
        declared=tuple(properties),
        auth_plugin=properties.get(AUTH_PLUGIN),
        crypto_plugin=properties.get(CRYPTO_PLUGIN),
        access_plugin=properties.get(ACCESS_PLUGIN),
        identity_crl=properties.get(IDENTITY_CRL),
        key_password=properties.get(KEY_PASSWORD),
        key_agreement=properties.get(KEY_AGREEMENT),
        legacy_algorithms=properties.get(LEGACY_ALGORITHMS),
    )
