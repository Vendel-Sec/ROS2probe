from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

from .files import file_facts
from .rmw_config import (
    EXPECTED_ACCESS_PLUGIN,
    EXPECTED_AUTH_PLUGIN,
    EXPECTED_CRYPTO_PLUGIN,
    SettingNames,
    XmlProfile,
)
from .xml_support import strip_namespaces, text_of

# A plugin is on when its element exists, and builtin unless <Library> says otherwise.
SECURITY = "Domain/Security"
AUTHENTICATION = f"{SECURITY}/Authentication"
ACCESS_CONTROL = f"{SECURITY}/AccessControl"
CRYPTOGRAPHIC = f"{SECURITY}/Cryptographic"

BUILTIN_LIBRARIES = {
    "Authentication": ("dds_security_auth", EXPECTED_AUTH_PLUGIN),
    "AccessControl": ("dds_security_ac", EXPECTED_ACCESS_PLUGIN),
    "Cryptographic": ("dds_security_crypto", EXPECTED_CRYPTO_PLUGIN),
}

# No key agreement or legacy-algorithm setting, so A.1.7 and A.1.8 do not apply.
CYCLONE_NAMES = SettingNames(
    vendor="Cyclone DDS",
    auth_plugin=AUTHENTICATION,
    crypto_plugin=CRYPTOGRAPHIC,
    access_plugin=ACCESS_CONTROL,
    identity_crl=f"{AUTHENTICATION}/CRL",
    key_password=f"{AUTHENTICATION}/Password",
)


def _library_stem(path: str) -> str:
    """`/opt/lib/libdds_security_auth.so` and `dds_security_auth` both give the stem."""
    name = PurePosixPath(path.replace("\\", "/")).name
    for suffix in (".so", ".dylib", ".dll"):
        name = name.split(suffix, 1)[0]
    return name.removeprefix("lib")


def _plugin(security: ET.Element, tag: str) -> str | None:
    """The builtin class name, or the library path of a non-builtin plugin."""
    element = security.find(tag)
    if element is None:
        return None
    library = element.find("Library")
    path = library.get("path", "").strip() if library is not None else ""
    builtin_stem, builtin_name = BUILTIN_LIBRARIES[tag]
    if not path or _library_stem(path) == builtin_stem:
        return builtin_name
    return path


def _declared(security: ET.Element) -> tuple[str, ...]:
    """Every leaf element under Security, as a path, for the failure message."""
    found: list[str] = []
    for section in security:
        children = list(section)
        if not children:
            found.append(f"{SECURITY}/{section.tag}")
        found.extend(f"{SECURITY}/{section.tag}/{child.tag}" for child in children)
    return tuple(found)


def parse_cyclonedds_config(path: Path) -> XmlProfile | None:
    """A Cyclone DDS configuration file, the one CYCLONEDDS_URI points at."""
    facts = file_facts(path)
    if not facts.exists:
        return None
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError) as exc:
        return XmlProfile(
            path=path, facts=facts, names=CYCLONE_NAMES, parse_error=str(exc),
        )

    strip_namespaces(root)
    # The first <Security> found, whether the root is <CycloneDDS> or <Domain>.
    security = root.find(".//Security") if root.tag != "Security" else root
    if security is None:
        return XmlProfile(path=path, facts=facts, names=CYCLONE_NAMES)

    authentication = security.find("Authentication")
    return XmlProfile(
        path=path,
        facts=facts,
        names=CYCLONE_NAMES,
        declared=_declared(security),
        auth_plugin=_plugin(security, "Authentication"),
        crypto_plugin=_plugin(security, "Cryptographic"),
        access_plugin=_plugin(security, "AccessControl"),
        identity_crl=text_of(authentication, "CRL"),
        key_password=text_of(authentication, "Password"),
    )
