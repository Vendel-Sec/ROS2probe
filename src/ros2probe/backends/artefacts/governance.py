import re
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .signatures import Signature, verify_signature
from .xml_support import (
    DomainRange,
    bool_of,
    domains_of,
    extract_dds_document,
    text_of,
)

ORIGIN_AUTH_SUFFIX = "_WITH_ORIGIN_AUTHENTICATION"


class BaseKind(StrEnum):
    NONE = "NONE"
    SIGN = "SIGN"
    ENCRYPT = "ENCRYPT"
    UNSET = "UNSET"


class ProtectionKind(BaseModel):
    """A `*_protection_kind` value, split into base kind and origin auth."""
    model_config = ConfigDict(frozen=True)

    raw: str
    base: BaseKind
    origin_authentication: bool

    @classmethod
    def parse(cls, raw: str | None) -> "ProtectionKind":
        text = (raw or "").strip().upper()
        if not text:
            return cls(raw="", base=BaseKind.UNSET, origin_authentication=False)
        has_origin_auth = text.endswith(ORIGIN_AUTH_SUFFIX)
        head = text.removesuffix(ORIGIN_AUTH_SUFFIX)
        try:
            base = BaseKind(head)
        except ValueError:
            base = BaseKind.UNSET
        return cls(raw=text, base=base, origin_authentication=has_origin_auth)

    @property
    def protects_integrity(self) -> bool:
        return self.base in (BaseKind.SIGN, BaseKind.ENCRYPT)

    @property
    def protects_confidentiality(self) -> bool:
        return self.base is BaseKind.ENCRYPT

    def __str__(self) -> str:
        return self.raw or "<unset>"


class TopicRule(BaseModel):
    """One `<topic_rule>`, with its position in the document preserved."""
    model_config = ConfigDict(frozen=True)

    index: int
    topic_expression: str
    enable_discovery_protection: bool | None = None
    enable_liveliness_protection: bool | None = None
    enable_read_access_control: bool | None = None
    enable_write_access_control: bool | None = None
    metadata_protection_kind: ProtectionKind
    data_protection_kind: ProtectionKind

    @property
    def is_wildcard(self) -> bool:
        return self.topic_expression.strip() in ("*", "**")

    @property
    def is_permissive(self) -> bool:
        """Whether this rule weakens anything relative to a locked-down rule."""
        return (
            self.enable_read_access_control is False
            or self.enable_write_access_control is False
            or self.enable_discovery_protection is False
            or self.enable_liveliness_protection is False
            or self.metadata_protection_kind.base is BaseKind.NONE
            or self.data_protection_kind.base is BaseKind.NONE
        )

    def matches(self, topic: str) -> bool:
        """fnmatch-style topic expression matching, as DDS-Security defines it."""
        pattern = (
            "^"
            + re.escape(self.topic_expression).replace(r"\*", ".*").replace(r"\?", ".")
            + "$"
        )
        return re.match(pattern, topic) is not None

    def describe(self) -> str:
        return (
            f"#{self.index} '{self.topic_expression}' "
            f"read_ac={self.enable_read_access_control} "
            f"write_ac={self.enable_write_access_control} "
            f"metadata={self.metadata_protection_kind} "
            f"data={self.data_protection_kind}"
            + ("  PERMISSIVE" if self.is_permissive else "")
        )


class DomainRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int
    domains: tuple[DomainRange, ...] = ()
    allow_unauthenticated_participants: bool | None = None
    enable_join_access_control: bool | None = None
    discovery_protection_kind: ProtectionKind
    liveliness_protection_kind: ProtectionKind
    rtps_protection_kind: ProtectionKind
    topic_rules: tuple[TopicRule, ...] = ()

    @property
    def domain_span(self) -> int:
        return sum(entry.span for entry in self.domains)

    def covers_domain(self, domain_id: int) -> bool:
        return any(entry.contains(domain_id) for entry in self.domains)

    def rule_for(self, topic: str) -> TopicRule | None:
        """First matching rule wins, which is the whole point of leaf A.3.8."""
        for rule in self.topic_rules:
            if rule.matches(topic):
                return rule
        return None


class Governance(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    signature: Signature
    domain_rules: tuple[DomainRule, ...] = ()

    @property
    def domain_rule(self) -> DomainRule:
        """The first domain rule."""
        if not self.domain_rules:
            raise AssertionError(f"no <domain_rule> in {self.path}")
        return self.domain_rules[0]

    def resolve(self, expressions: tuple[str, ...]) -> tuple[tuple[str, TopicRule], ...]:
        """The rule that actually governs each named topic, by first match."""
        found: list[tuple[str, TopicRule]] = []
        for expression in expressions:
            rule = self.domain_rule.rule_for(expression)
            if rule is not None:
                found.append((expression, rule))
        return tuple(found)


def parse_governance(path: Path, ca_certificate: Path | None) -> Governance | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    root = extract_dds_document(text)
    if root is None:
        return None

    rules: list[DomainRule] = []
    for domain_index, rule_element in enumerate(
        root.findall("./domain_access_rules/domain_rule")
    ):
        topic_rules: list[TopicRule] = []
        container = rule_element.find("topic_access_rules")
        elements = container.findall("topic_rule") if container is not None else []
        for topic_index, topic_element in enumerate(elements):
            topic_rules.append(TopicRule(
                index=topic_index,
                topic_expression=text_of(topic_element, "topic_expression") or "",
                enable_discovery_protection=bool_of(
                    topic_element, "enable_discovery_protection"),
                enable_liveliness_protection=bool_of(
                    topic_element, "enable_liveliness_protection"),
                enable_read_access_control=bool_of(
                    topic_element, "enable_read_access_control"),
                enable_write_access_control=bool_of(
                    topic_element, "enable_write_access_control"),
                metadata_protection_kind=ProtectionKind.parse(
                    text_of(topic_element, "metadata_protection_kind")),
                data_protection_kind=ProtectionKind.parse(
                    text_of(topic_element, "data_protection_kind")),
            ))

        rules.append(DomainRule(
            index=domain_index,
            domains=domains_of(rule_element),
            allow_unauthenticated_participants=bool_of(
                rule_element, "allow_unauthenticated_participants"),
            enable_join_access_control=bool_of(
                rule_element, "enable_join_access_control"),
            discovery_protection_kind=ProtectionKind.parse(
                text_of(rule_element, "discovery_protection_kind")),
            liveliness_protection_kind=ProtectionKind.parse(
                text_of(rule_element, "liveliness_protection_kind")),
            rtps_protection_kind=ProtectionKind.parse(
                text_of(rule_element, "rtps_protection_kind")),
            topic_rules=tuple(topic_rules),
        ))

    return Governance(
        path=path,
        signature=verify_signature(path, ca_certificate),
        domain_rules=tuple(rules),
    )
