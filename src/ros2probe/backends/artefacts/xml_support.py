import base64
import binascii
import datetime as dt
import re
from xml.etree import ElementTree as ET

from pydantic import BaseModel, ConfigDict

DDS_DOC_RE = re.compile(r"<dds\b.*?</dds>", re.DOTALL | re.IGNORECASE)


class DomainRange(BaseModel):
    """A `<domains>` entry, either a single `<id>` or an `<id_range>`."""
    model_config = ConfigDict(frozen=True)

    low: int
    high: int

    @property
    def span(self) -> int:
        return self.high - self.low + 1

    def contains(self, domain_id: int) -> bool:
        return self.low <= domain_id <= self.high

    def __str__(self) -> str:
        return str(self.low) if self.low == self.high else f"{self.low}-{self.high}"


def strip_namespaces(element: ET.Element) -> None:
    """Drop namespace prefixes in place, so `find("dds")` works on any document."""
    for node in element.iter():
        if isinstance(node.tag, str) and "}" in node.tag:
            node.tag = node.tag.split("}", 1)[1]


def text_of(parent: ET.Element | None, tag: str) -> str | None:
    """The element's text, or None when the element is absent or empty."""
    if parent is None:
        return None
    element = parent.find(tag)
    if element is None or element.text is None:
        return None
    return element.text.strip()


def bool_of(parent: ET.Element | None, tag: str) -> bool | None:
    """True, False, or None when the element is absent."""
    raw = text_of(parent, tag)
    if raw is None:
        return None
    return raw.strip().lower() == "true"


def domains_of(parent: ET.Element | None) -> tuple[DomainRange, ...]:
    if parent is None:
        return ()
    node = parent.find("domains")
    if node is None:
        return ()
    found: list[DomainRange] = []
    for child in node:
        if child.tag == "id" and child.text:
            value = int(child.text.strip())
            found.append(DomainRange(low=value, high=value))
        elif child.tag == "id_range":
            low = text_of(child, "min")
            high = text_of(child, "max")
            base = int(low) if low else 0
            found.append(DomainRange(
                low=base, high=int(high) if high else base,
            ))
    return tuple(found)


def parse_timestamp(raw: str | None) -> dt.datetime | None:
    """An ISO timestamp from a `<validity>` element, normalised to UTC."""
    if not raw:
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed


def _from_opaque_pkcs7(text: str) -> str | None:
    """The <dds> document inside an opaque S/MIME or PEM PKCS7 wrapper.

    `ros2 security create_keystore` signs governance and permissions with
    smime-type=signed-data, so the document is base64 inside the PKCS7 rather
    than in the clear beside it. Every real sros2 keystore looks like this, and
    a reader that only searches the raw text decides nothing against one.
    """
    body = text.split("\n\n", 1)[1] if "\n\n" in text else text
    encoded = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    if not encoded:
        return None
    try:
        blob = base64.b64decode(encoded, validate=False)
    except (ValueError, binascii.Error):
        return None
    match = DDS_DOC_RE.search(blob.decode("utf-8", errors="replace"))
    return match.group(0) if match else None


def extract_dds_document(text: str) -> ET.Element | None:
    """Pull the `<dds>` document out of a .p7s wrapper or a plain .xml file."""
    match = DDS_DOC_RE.search(text)
    document = match.group(0) if match else _from_opaque_pkcs7(text)
    if document is None:
        return None
    try:
        root = ET.fromstring(document)
    except ET.ParseError:
        return None
    strip_namespaces(root)
    return root
