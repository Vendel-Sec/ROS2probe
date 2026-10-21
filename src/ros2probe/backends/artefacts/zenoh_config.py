from pathlib import Path
from typing import Any

import json5
from pydantic import BaseModel, ConfigDict

from .files import FileFacts, file_facts

# Link protocols that encrypt. Anything else on an endpoint is plaintext.
ENCRYPTED_PROTOCOLS = frozenset({"tls", "quic"})

ROUTER_FILENAME = "zenohd.json5"
SESSION_FILENAME = "zenoh_session.json5"


class AclRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = ""
    permission: str = ""
    messages: tuple[str, ...] = ()
    flows: tuple[str, ...] = ()
    key_exprs: tuple[str, ...] = ()


class AclSubject(BaseModel):
    """One ACL subject. A null property matches anything, so all-null matches every peer."""
    model_config = ConfigDict(frozen=True)

    id: str = ""
    cert_common_names: tuple[str, ...] | None = None
    interfaces: tuple[str, ...] | None = None
    usernames: tuple[str, ...] | None = None
    zids: tuple[str, ...] | None = None
    link_protocols: tuple[str, ...] | None = None

    @property
    def matches_any_peer(self) -> bool:
        return all(
            value is None for value in (
                self.cert_common_names, self.interfaces, self.usernames,
                self.zids, self.link_protocols,
            )
        )


class AclPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = ""
    rules: tuple[str, ...] = ()
    subjects: tuple[str, ...] = ()


class ZenohConfig(BaseModel):
    """The security settings of one Zenoh router or session config. None means the key is absent."""
    model_config = ConfigDict(frozen=True)

    path: Path
    facts: FileFacts
    parse_error: str = ""

    mode: str | None = None
    listen_endpoints: tuple[str, ...] = ()
    connect_endpoints: tuple[str, ...] = ()
    link_protocols: tuple[str, ...] | None = None

    tls_root_ca_certificate: str | None = None
    tls_listen_certificate: str | None = None
    tls_listen_private_key: str | None = None
    tls_connect_certificate: str | None = None
    tls_connect_private_key: str | None = None
    tls_enable_mtls: bool | None = None
    tls_verify_name_on_connect: bool | None = None

    usrpwd_user: str | None = None
    usrpwd_password: str | None = None
    usrpwd_dictionary_file: str | None = None

    acl_present: bool = False
    acl_enabled: bool | None = None
    acl_default_permission: str | None = None
    acl_rules: tuple[AclRule, ...] = ()
    acl_subjects: tuple[AclSubject, ...] = ()
    acl_policies: tuple[AclPolicy, ...] = ()

    adminspace_enabled: bool | None = None
    adminspace_read: bool | None = None
    adminspace_write: bool | None = None
    multicast_scouting: bool | None = None
    gossip_scouting: bool | None = None
    shared_memory: bool | None = None

    @property
    def endpoints(self) -> tuple[str, ...]:
        return self.listen_endpoints + self.connect_endpoints

    @property
    def plaintext_endpoints(self) -> tuple[str, ...]:
        return tuple(
            e for e in self.endpoints
            if e.split("/", 1)[0].lower() not in ENCRYPTED_PROTOCOLS
        )

    @property
    def exposed_plaintext_listeners(self) -> tuple[str, ...]:
        """Plaintext listen endpoints off loopback, where mTLS cannot apply and any host joins."""
        return tuple(
            e for e in self.listen_endpoints
            if e.split("/", 1)[0].lower() not in ENCRYPTED_PROTOCOLS
            and not _is_loopback(e)
        )

    @property
    def acl_enforced(self) -> bool:
        return self.acl_present and self.acl_enabled is True

    @property
    def subjects_matching_any_peer(self) -> tuple[AclSubject, ...]:
        return tuple(s for s in self.acl_subjects if s.matches_any_peer)


LOOPBACK_HOSTS = ("localhost", "127.", "[::1]")


def _is_loopback(endpoint: str) -> bool:
    address = endpoint.split("/", 1)[-1].lower()
    return address.startswith(LOOPBACK_HOSTS)


def _get(tree: Any, path: str) -> Any:
    """The value at a slash-separated key path, or None when any step is missing."""
    node = tree
    for part in path.split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _strings(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def _endpoints(value: Any, mode: str | None) -> tuple[str, ...]:
    """A list, or a per-mode object as Zenoh 1.x also accepts, flattened for this mode."""
    if isinstance(value, dict):
        chosen = value.get(mode) if mode in value else [
            item for items in value.values() for item in (items or [])
        ]
        return _strings(chosen) or ()
    return _strings(value) or ()


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


TEXT_FIELDS = frozenset({"id", "permission"})


def _models(items: Any, model: type[BaseModel]) -> tuple[Any, ...]:
    """ACL entries as models. A null property is left out, so it keeps its wildcard default."""
    if not isinstance(items, list):
        return ()
    found = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fields = {
            key: str(value) if key in TEXT_FIELDS else _strings(value)
            for key, value in item.items()
            if key in model.model_fields and value is not None
        }
        found.append(model(**fields))
    return tuple(found)


def parse_zenoh_config(path: Path) -> ZenohConfig | None:
    """A Zenoh JSON5 config, router or session. None when the file is absent."""
    facts = file_facts(path)
    if not facts.exists:
        return None
    try:
        tree = json5.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ZenohConfig(path=path, facts=facts, parse_error=str(exc))
    if not isinstance(tree, dict):
        return ZenohConfig(path=path, facts=facts, parse_error="top level is not an object")

    mode = _text(_get(tree, "mode"))
    tls = "transport/link/tls"
    usrpwd = "transport/auth/usrpwd"
    acl = _get(tree, "access_control")
    return ZenohConfig(
        path=path,
        facts=facts,
        mode=mode,
        listen_endpoints=_endpoints(_get(tree, "listen/endpoints"), mode),
        connect_endpoints=_endpoints(_get(tree, "connect/endpoints"), mode),
        link_protocols=_strings(_get(tree, "transport/link/protocols")),
        tls_root_ca_certificate=_text(_get(tree, f"{tls}/root_ca_certificate")),
        tls_listen_certificate=_text(_get(tree, f"{tls}/listen_certificate")),
        tls_listen_private_key=_text(_get(tree, f"{tls}/listen_private_key")),
        tls_connect_certificate=_text(_get(tree, f"{tls}/connect_certificate")),
        tls_connect_private_key=_text(_get(tree, f"{tls}/connect_private_key")),
        tls_enable_mtls=_bool(_get(tree, f"{tls}/enable_mtls")),
        tls_verify_name_on_connect=_bool(_get(tree, f"{tls}/verify_name_on_connect")),
        usrpwd_user=_text(_get(tree, f"{usrpwd}/user")),
        usrpwd_password=_text(_get(tree, f"{usrpwd}/password")),
        usrpwd_dictionary_file=_text(_get(tree, f"{usrpwd}/dictionary_file")),
        acl_present=isinstance(acl, dict),
        acl_enabled=_bool(_get(tree, "access_control/enabled")),
        acl_default_permission=_text(_get(tree, "access_control/default_permission")),
        acl_rules=_models(_get(tree, "access_control/rules"), AclRule),
        acl_subjects=_models(_get(tree, "access_control/subjects"), AclSubject),
        acl_policies=_models(_get(tree, "access_control/policies"), AclPolicy),
        adminspace_enabled=_bool(_get(tree, "adminspace/enabled")),
        adminspace_read=_bool(_get(tree, "adminspace/permissions/read")),
        adminspace_write=_bool(_get(tree, "adminspace/permissions/write")),
        multicast_scouting=_bool(_get(tree, "scouting/multicast/enabled")),
        gossip_scouting=_bool(_get(tree, "scouting/gossip/enabled")),
        shared_memory=_bool(_get(tree, "transport/shared_memory/enabled")),
    )
