import datetime as dt
import fnmatch
from pathlib import Path
from xml.etree import ElementTree as ET

from pydantic import BaseModel, ConfigDict

from .signatures import Signature, verify_signature
from .xml_support import (
    DomainRange,
    domains_of,
    extract_dds_document,
    parse_timestamp,
    text_of,
)

WILDCARDS = ("*", "**")
CRITERIA_VERBS = ("publish", "subscribe", "relay")


class Validity(BaseModel):
    model_config = ConfigDict(frozen=True)

    not_before: dt.datetime | None = None
    not_after: dt.datetime | None = None

    @property
    def days(self) -> int | None:
        if self.not_before is None or self.not_after is None:
            return None
        return (self.not_after - self.not_before).days

    @property
    def remaining_days(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - dt.datetime.now(dt.UTC)).days

    @property
    def is_bounded(self) -> bool:
        return self.not_after is not None


class Criteria(BaseModel):
    """A `<publish>`, `<subscribe>` or `<relay>` block inside a rule."""
    model_config = ConfigDict(frozen=True)

    verb: str
    topics: tuple[str, ...] = ()
    partitions: tuple[str, ...] = ()

    @property
    def has_wildcard(self) -> bool:
        return any(topic.strip() in WILDCARDS for topic in self.topics)


class Rule(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: str                     # "allow" | "deny"
    domains: tuple[DomainRange, ...] = ()
    criteria: tuple[Criteria, ...] = ()

    def by_verb(self, verb: str) -> Criteria | None:
        for item in self.criteria:
            if item.verb == verb:
                return item
        return None

    @property
    def has_wildcard(self) -> bool:
        return any(item.has_wildcard for item in self.criteria)

    @property
    def has_relay(self) -> bool:
        return self.by_verb("relay") is not None


class Grant(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    subject_name: str = ""
    validity: Validity = Validity()
    rules: tuple[Rule, ...] = ()
    default: str = ""             # ALLOW | DENY | "" when the element is absent

    @property
    def allow_rules(self) -> tuple[Rule, ...]:
        return tuple(rule for rule in self.rules if rule.kind == "allow")

    @property
    def subject_is_wildcard(self) -> bool:
        subject = self.subject_name.strip()
        return subject == "" or subject in WILDCARDS or "*" in subject

    @property
    def effective_default(self) -> str:
        """The specification's implied default with no `<default>` element is DENY."""
        return (self.default or "DENY").upper()


class Permissions(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    signature: Signature
    grants: tuple[Grant, ...] = ()

    @property
    def allowed_topics(self) -> frozenset[str]:
        """DDS topic names an allow rule grants, wildcards left out."""
        return frozenset(
            topic for grant in self.grants for rule in grant.allow_rules
            for criteria in rule.criteria for topic in criteria.topics if "*" not in topic
        )

    def grants_topic(self, topic: str) -> bool:
        return any(
            fnmatch.fnmatchcase(topic, pattern) for grant in self.grants
            for rule in grant.allow_rules for criteria in rule.criteria for pattern in criteria.topics
        )

    @property
    def enclave_name(self) -> str:
        """The enclave directory this document belongs to, for failure messages."""
        return self.path.parent.name


def _texts(element: ET.Element, path: str) -> tuple[str, ...]:
    return tuple(item.text.strip() for item in element.findall(path) if item.text)


def _criteria(element: ET.Element, verb: str) -> Criteria:
    return Criteria(
        verb=verb,
        topics=_texts(element, "topics/topic"),
        partitions=_texts(element, "partitions/partition"),
    )


def _rule(element: ET.Element, kind: str) -> Rule:
    return Rule(
        kind=kind,
        domains=domains_of(element),
        criteria=tuple(
            _criteria(criteria_element, verb)
            for verb in CRITERIA_VERBS
            for criteria_element in element.findall(verb)
        ),
    )


def _grant(element: ET.Element) -> Grant:
    validity_element = element.find("validity")
    return Grant(
        name=element.get("name", ""),
        subject_name=text_of(element, "subject_name") or "",
        validity=Validity(
            not_before=parse_timestamp(text_of(validity_element, "not_before")),
            not_after=parse_timestamp(text_of(validity_element, "not_after")),
        ),
        rules=tuple(
            _rule(rule_element, kind)
            for kind in ("allow", "deny")
            for rule_element in element.findall(f"{kind}_rule")
        ),
        default=text_of(element, "default") or "",
    )


def parse_permissions(path: Path, ca_certificate: Path | None) -> Permissions | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    root = extract_dds_document(text)
    if root is None:
        return None
    return Permissions(
        path=path,
        signature=verify_signature(path, ca_certificate),
        grants=tuple(_grant(element) for element in root.findall("./permissions/grant")),
    )
