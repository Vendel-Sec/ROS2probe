# pytest hook signatures are fixed by pytest, not by us.

import errno
import logging
import shutil
from collections.abc import Generator
from pathlib import Path

import pytest

from ros2probe.backends.artefacts import (
    EnvSource,
    Governance,
    Keystore,
    Permissions,
    RuntimeEnv,
    read_keystore,
)
from ros2probe.backends.artefacts.rmw_config import Family
from ros2probe.backends.dds import DdsClient
from ros2probe.backends.dds.zenoh_router import (
    RouterProbe,
    RouterTransport,
    probe_router,
    split_endpoint,
)
from ros2probe.backends.host import HostShell
from ros2probe.backends.net import NetScan, scan
from ros2probe.backends.wire import Capture, capture_or_load
from ros2probe.targets.profile import TargetProfile, Transport

LOG = logging.getLogger(__name__)


class SetupError(Exception):
    """The run is broken: an ERROR, never a finding."""


def run_dir(config: pytest.Config) -> Path | None:
    """Where this run's evidence goes, so the pcap and the keystore join the log."""
    log = config.getoption("log_file") or config.getini("log_file")
    return Path(log).parent if log else None

# Target and safety

def _readable(path: Path, kind: str) -> str:
    """Empty if the path is a readable file/dir, else what is wrong with it."""
    try:
        ok = path.is_dir() if kind == "directory" else path.is_file()
    except OSError as error:
        return f"cannot read {path}: {error.strerror}"
    return "" if ok else f"does not exist: {path}"



@pytest.fixture(scope="session")
def profile(pytestconfig: pytest.Config) -> TargetProfile:
    path = Path(pytestconfig.getoption("--target")).expanduser()
    problem = _readable(path, "file")
    if problem:
        pytest.exit(f"target profile {problem}", returncode=2)
    loaded = TargetProfile.load(path)
    LOG.info("target %s from %s: address %s, rmw %s", loaded.name, path,
             loaded.robot.address, loaded.ros.rmw)
    return loaded


# Artefact fixtures

def copy_artefacts(root: Path, into: Path) -> None:
    """The keystore beside the log, minus the keys."""
    copied, withheld = 0, []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if "key" in path.name:
            withheld.append(str(path))
            continue
        destination = into / path.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        copied += 1
    LOG.debug("copied %d artefacts to %s, withheld %s", copied, into, withheld)


@pytest.fixture(scope="session")
def keystore(profile: TargetProfile, pytestconfig: pytest.Config) -> Keystore:
    path = profile.copies.keystore
    if path is None:
        pytest.skip("copies.keystore not set")
    problem = _readable(path, "directory")
    if problem:
        raise SetupError(f"copies.keystore {problem}")
    for path_set in (profile.copies.profile, profile.copies.router_config):
        if path_set is not None and not path_set.is_file():
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", str(path_set))
    parsed = read_keystore(
        path, rmw=profile.ros.rmw, profile_path=profile.copies.profile,
        zenoh_router_path=profile.copies.router_config,
    )
    into = run_dir(pytestconfig)
    if into is not None:
        copy_artefacts(path, into / "files")
    if not parsed.enclaves:
        raise SetupError(f"no readable enclaves under {path}: {'; '.join(parsed.errors)}")
    return parsed


@pytest.fixture(scope="session")
def granted_topics(keystore: Keystore, profile: TargetProfile) -> tuple[str, ...]:
    """DDS names of the topics the permissions grant, plus the profile's actuation topics."""
    topics = tuple(sorted({*keystore.topics, *(t.dds_name for t in profile.ros.actuation_topics)}))
    for topic in topics:
        LOG.info("granted topic %s", topic)
    return topics


@pytest.fixture(scope="session")
def governance(keystore: Keystore) -> Governance:
    document = keystore.any_governance
    if document is None:
        pytest.skip("no governance.p7s in the keystore")
    if not document.domain_rules:
        pytest.skip(f"no <domain_rule> element in {document.path}")
    return document


@pytest.fixture(scope="session")
def permissions(keystore: Keystore) -> tuple[Permissions, ...]:
    """Every enclave's permissions document, so a test can compare across them."""
    documents = keystore.all_permissions
    if not documents:
        pytest.skip("no permissions.p7s in the keystore")
    return documents


@pytest.fixture(scope="session")
def target_env(host: HostShell) -> RuntimeEnv:
    pids = host.ros_process_pids()
    if not pids:
        pytest.skip(f"no process matching {host.robot.ros_process_pattern!r}")
    for pid in pids:
        variables = host.process_environ(pid)
        if variables is not None:
            return RuntimeEnv.from_variables(variables, source=EnvSource.PROCESS, origin=f"/proc/{pid}/environ")
    pytest.skip(f"cannot read the environment of ROS processes {pids}")


# Live backends

def _is_loopback(address: str) -> bool:
    return address.strip("[]").startswith(("127.", "::1", "::ffff:127."))


def _router_binds(request: pytest.FixtureRequest, port: int) -> list[str]:
    """Where the router listens, from the host, or empty without host access."""
    try:
        host = request.getfixturevalue("host")
    except (pytest.skip.Exception, SetupError):
        return []
    return host.listen_addresses(port)


@pytest.fixture(scope="session")
def zenoh_router(profile: TargetProfile, request: pytest.FixtureRequest) -> RouterProbe:
    """The router, or the zenoh bridge, as the network sees it."""
    router = profile.zenoh_router
    found = probe_router(*split_endpoint(router))
    if found.transport is RouterTransport.UNREACHABLE:
        bound = _router_binds(request, split_endpoint(router)[1])
        if bound and all(_is_loopback(a) for a in bound):
            pytest.skip(f"router listens on localhost only: {', '.join(bound)}")
        raise SetupError(f"zenoh router {router} unreachable: {found.detail}"
                         + (f", host listens on {', '.join(bound)}" if bound else ""))
    return found


@pytest.fixture(scope="session")
def dds(
    profile: TargetProfile, pytestconfig: pytest.Config, request: pytest.FixtureRequest,
) -> Generator[DdsClient, None, None]:
    client = DdsClient(profile=profile)
    if profile.ros.rmw.family is Family.ZENOH:
        request.getfixturevalue("zenoh_router")
    else:
        result = client.anonymous_graph()
        if not result.participant_created:
            raise SetupError(f"cannot create a DDS participant: {result.undecided_reason()}")
    yield client
    into = run_dir(pytestconfig)
    if into is not None:
        written = client.save_graphs(into / "graph")
        if written:
            LOG.debug("saved %d graph snapshot(s) to %s", len(written), into / "graph")


@pytest.fixture(scope="session")
def host(profile: TargetProfile) -> HostShell:
    if profile.robot.transport is Transport.NONE:
        pytest.skip("robot.ssh not set")
    shell = HostShell(robot=profile.robot)
    probe = shell.run("true")
    if not probe.ok:
        raise SetupError(f"host unreachable via {shell.position}\n{probe}")
    LOG.info("host commands via %s", shell.position)
    return shell


@pytest.fixture(scope="session")
def netscan(profile: TargetProfile) -> NetScan:
    return scan(profile.robot)


@pytest.fixture(scope="session")
def capture(profile: TargetProfile, pytestconfig: pytest.Config) -> Capture:
    into = run_dir(pytestconfig)
    return capture_or_load(
        profile.capture, destination=into / "capture.pcap" if into else None,
    )


# The safety gate, enforced before every intrusive test

def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("intrusive") and not item.config.getoption("--arm"):
        pytest.skip("intrusive: needs --arm")


# Collection and reporting

def _leaf_of(item: pytest.Item) -> str | None:
    marker = item.get_closest_marker("leaf")
    if marker is None or not marker.args:
        return None
    leaf_id = marker.args[0]
    return leaf_id if isinstance(leaf_id, str) else None


BACKENDS = ("static", "dds", "host", "wire", "net")


def _backends_of(item: pytest.Item) -> str:
    return "+".join(
        name for name in BACKENDS if item.get_closest_marker(name) is not None
    )


def _tags_of(item: pytest.Item) -> list[str]:
    """The leaf ID and the backend, as they are appended to a test's name."""
    leaf_id = _leaf_of(item)
    backends = _backends_of(item)
    tags = []
    if leaf_id is not None:
        tags.append(f"[{leaf_id}]")
    if backends:
        tags.append(f"({backends})")
    return tags


# Zenoh has no RTPS and no DDS-Security documents.
DDS_ONLY_FIXTURES = ("governance", "permissions", "capture")


def _applies(item: pytest.Item, family: Family) -> bool:
    marker = item.get_closest_marker("rmw")
    if marker is not None and family not in marker.args:
        return False
    return not (family is Family.ZENOH and set(DDS_ONLY_FIXTURES) & set(getattr(item, "fixturenames", ())))


def _deselect_not_applicable(config: pytest.Config, items: list[pytest.Item]) -> None:
    try:
        ros = TargetProfile.load(Path(config.getoption("--target")).expanduser()).ros
    except (OSError, ValueError):
        return
    dropped = [item for item in items if not _applies(item, ros.rmw.family)]
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = [item for item in items if item not in dropped]


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item],
) -> None:
    """Drop the tests that do not apply to the target's rmw, then tag the node IDs."""
    _deselect_not_applicable(config, items)
    for item in items:
        leaf_id = _leaf_of(item)
        if leaf_id is not None:
            item.extra_keyword_matches.add(leaf_id)
        tags = _tags_of(item)
        if tags:
            item._nodeid = " ".join([item.nodeid, *tags])


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo,
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    """Put the leaf ID and the backend in the headline."""
    report = yield
    if call.excinfo is not None and isinstance(call.excinfo.value, SetupError | OSError):
        report.longrepr = f"{call.excinfo.typename}: {call.excinfo.value}"
    tags = _tags_of(item)
    if tags:
        path, lineno, domain = report.location
        report.location = (path, lineno, " ".join([domain, *tags]))
    return report


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Every outcome in run.log, next to the backend lines that produced it."""
    if report.when == "call" or report.outcome != "passed":
        reason = report.longrepr[2] if report.skipped and isinstance(report.longrepr, tuple) else ""
        LOG.info("%s %s %s %s", report.outcome.upper(), report.when, report.nodeid, reason)
