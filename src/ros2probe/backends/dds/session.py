import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, PrivateAttr

from ...targets.profile import TargetProfile, TopicSpec
from ..artefacts.rmw_config import is_zenoh
from .protocol import Job, JobKind, WorkerResult
from .zenoh_router import RouterTransport, probe_router, split_endpoint, zenoh_override

WORKER_MODULE = "ros2probe.backends.dds.worker"

LOG = logging.getLogger(__name__)

# Environment variables that must never leak from the runner into a session that
# is supposed to be unauthenticated. A T1 test that accidentally authenticates
# reports the opposite of the truth.
CREDENTIAL_VARIABLES = (
    "ROS_SECURITY_ENABLE",
    "ROS_SECURITY_STRATEGY",
    "ROS_SECURITY_KEYSTORE",
    "ROS_SECURITY_ENCLAVE_OVERRIDE",
)

# Zenoh settings the runner may carry, which a probe session must not inherit.
ZENOH_VARIABLES = (
    "ZENOH_ROUTER_CONFIG_URI",
    "ZENOH_SESSION_CONFIG_URI",
    "ZENOH_CONFIG_OVERRIDE",
)

WORKER_TIMEOUT_PAD_S = 12.0
DISCOVERY_TIMEOUT_S = 8.0
READ_TIMEOUT_S = 6.0
MATCH_TIMEOUT_S = 6.0
DOMAIN_SCAN_TIMEOUT_S = 4.0
STDERR_TAIL_LINES = 8


class DdsSession(BaseModel):
    """One attacker position against one domain."""
    model_config = ConfigDict(frozen=True)

    label: str
    domain_id: int
    secure: bool = False
    keystore: Path | None = None
    enclave: str | None = None
    # Empty keeps the runner's RMW_IMPLEMENTATION.
    rmw: str = ""
    # The robot's Zenoh router as host:port, dialled when rmw is rmw_zenoh_cpp.
    zenoh_router: str = ""

    @classmethod
    def anonymous(
        cls, profile: TargetProfile, domain_id: int | None = None,
    ) -> "DdsSession":
        return cls(
            label="T1 anonymous",
            domain_id=profile.ros.domain if domain_id is None else domain_id,
            rmw=profile.probe_rmw,
            zenoh_router=profile.zenoh_router,
        )

    @classmethod
    def credentialed(cls, profile: TargetProfile) -> "DdsSession":
        held = profile.credentials
        return cls(
            label=f"T2 enclave {held.enclave if held else None}",
            domain_id=profile.ros.domain,
            secure=True,
            keystore=held.keystore if held else None,
            enclave=held.enclave if held else None,
            rmw=profile.probe_rmw,
            zenoh_router=profile.zenoh_router,
        )

    @property
    def available(self) -> bool:
        if not self.secure:
            return True
        return bool(
            self.keystore and self.enclave and Path(self.keystore).is_dir()
        )

    def _environment(self, zenoh_override_value: str = "") -> dict[str, str]:
        # A process environment is inherently a name-to-value mapping, and this is
        # the shape subprocess.Popen requires.
        environment = dict(os.environ)
        environment["ROS_DOMAIN_ID"] = str(self.domain_id)
        if self.rmw:
            environment["RMW_IMPLEMENTATION"] = self.rmw
        for name in CREDENTIAL_VARIABLES + ZENOH_VARIABLES:
            environment.pop(name, None)
        if zenoh_override_value:
            environment["ZENOH_CONFIG_OVERRIDE"] = zenoh_override_value
        if self.secure:
            environment["ROS_SECURITY_ENABLE"] = "true"
            environment["ROS_SECURITY_STRATEGY"] = "Enforce"
            environment["ROS_SECURITY_KEYSTORE"] = str(self.keystore)
        environment.setdefault("PYTHONUNBUFFERED", "1")
        return environment

    def _argv(self) -> list[str]:
        argv = [sys.executable, "-m", WORKER_MODULE]
        if self.secure and self.enclave:
            argv += ["--ros-args", "--enclave", self.enclave]
        return argv

    def run(self, job: Job) -> WorkerResult:
        override = ""
        if is_zenoh(self.rmw):
            early, override = self._zenoh_route()
            if early is not None:
                LOG.debug("%s: %s -> %s", self.label, job, early)
                return early
        result = self._execute(job, override)
        LOG.debug("%s domain %s: %s -> %s", self.label, self.domain_id, job, result)
        return result

    def _zenoh_route(self) -> tuple[WorkerResult | None, str]:
        """Probe the router, then either answer without a session or say how to dial it."""
        host, port = split_endpoint(self.zenoh_router)
        found = probe_router(host, port)
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        LOG.debug("%s: router %s answered %s, %s", self.label, address,
                  found.transport, found.detail)
        if found.transport is RouterTransport.UNREACHABLE:
            return WorkerResult(error=found.detail), ""
        if found.transport is RouterTransport.NOT_TLS:
            return None, zenoh_override(f"tcp/{address}", None)
        if not self.secure:
            if found.transport is RouterTransport.MTLS:
                return WorkerResult(ok=True, refused_by_router=True,
                                    router_detail=found.detail), ""
            return WorkerResult(error=f"the router speaks TLS without demanding a "
                                      f"client certificate ({found.detail}). The probe "
                                      "has no CA to verify it with, so the T1 question "
                                      "is undecided. A.1.1 reports the router itself"), ""
        enclave_dir = Path(self.keystore or ".") / "enclaves" / (self.enclave or "").strip("/")
        return None, zenoh_override(f"tls/{address}", enclave_dir)

    def _execute(self, job: Job, zenoh_override_value: str = "") -> WorkerResult:
        timeout = job.timeout_s + WORKER_TIMEOUT_PAD_S
        try:
            proc = subprocess.run(
                self._argv(),
                input=job.model_dump_json(),
                capture_output=True, text=True,
                env=self._environment(zenoh_override_value),
                timeout=timeout,
                check=False,
                cwd=str(Path(__file__).resolve().parents[3]),
            )
        except subprocess.TimeoutExpired:
            return WorkerResult(
                ok=False,
                error=f"DDS worker timed out after {timeout}s ({self.label}, "
                      f"domain {self.domain_id}, job {job.kind})",
            )
        except (OSError, FileNotFoundError) as exc:
            return WorkerResult(ok=False, error=f"cannot start DDS worker: {exc}")

        stderr_tail = "\n".join(proc.stderr.strip().splitlines()[-STDERR_TAIL_LINES:])
        # The worker prints exactly one JSON object on stdout. Anything else there
        # is ROS logging noise, so take the last line that parses.
        for line in reversed(proc.stdout.strip().splitlines()):
            try:
                parsed = WorkerResult.model_validate_json(line)
            except ValueError:
                continue
            return parsed.model_copy(update={"stderr_tail": stderr_tail})

        return WorkerResult(
            ok=False,
            error=f"DDS worker produced no parseable result (exit {proc.returncode})",
            stderr_tail=stderr_tail,
        )

    # --- one wrapper per observation a test needs -------------------------- #

    def graph(self, timeout_s: float) -> WorkerResult:
        return self.run(Job(kind=JobKind.GRAPH, timeout_s=timeout_s))

    def read(self, topic: str, type_name: str, timeout_s: float) -> WorkerResult:
        return self.run(
            Job(kind=JobKind.READ, topic=topic, type=type_name, timeout_s=timeout_s)
        )

    def write_match(
        self,
        topic: str,
        type_name: str,
        timeout_s: float,
        publish_count: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> WorkerResult:
        return self.run(Job(
            kind=JobKind.WRITE_MATCH, topic=topic, type=type_name, timeout_s=timeout_s,
            publish_count=publish_count, payload=payload or {},
        ))

    def params(
        self, target_node: str, names: tuple[str, ...], timeout_s: float,
    ) -> WorkerResult:
        return self.run(Job(
            kind=JobKind.PARAMS, target_node=target_node, param_names=names,
            timeout_s=timeout_s,
        ))


class DdsClient(BaseModel):
    """The `dds` fixture."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    profile: TargetProfile
    _graph_cache: dict[str, WorkerResult] = PrivateAttr(default_factory=dict)

    @property
    def anonymous(self) -> DdsSession:
        return DdsSession.anonymous(self.profile)

    @property
    def credentialed(self) -> DdsSession:
        return DdsSession.credentialed(self.profile)

    def anonymous_graph(self) -> WorkerResult:
        key = f"anonymous:{self.profile.ros.domain}"
        if key not in self._graph_cache:
            self._graph_cache[key] = self.anonymous.graph(DISCOVERY_TIMEOUT_S)
        return self._graph_cache[key]

    def credentialed_graph(self) -> WorkerResult:
        key = f"credentialed:{self.profile.ros.domain}"
        if key not in self._graph_cache:
            self._graph_cache[key] = self.credentialed.graph(DISCOVERY_TIMEOUT_S)
        return self._graph_cache[key]

    def credentialed_topics(self) -> tuple[TopicSpec, ...]:
        """Every topic the held credential's graph shows."""
        topics = tuple(TopicSpec(name=t.name, type=t.types[0] if t.types else "")
                       for t in sorted(self.credentialed_graph().topics, key=lambda t: t.name))
        for topic in topics:
            LOG.info("discovered topic %s %s", topic.name, topic.type or "?")
        return topics

    def scan_domains(self) -> tuple[tuple[int, WorkerResult], ...]:
        """One anonymous discovery attempt per domain in the profile's scan list."""
        results = []
        for domain in self.profile.ros.domain_scan:
            key = f"scan:{domain}"
            if key not in self._graph_cache:
                self._graph_cache[key] = DdsSession.anonymous(
                    self.profile, domain_id=domain
                ).graph(DOMAIN_SCAN_TIMEOUT_S)
            results.append((domain, self._graph_cache[key]))
        return tuple(results)

    def save_graphs(self, into: Path) -> tuple[Path, ...]:
        """Write every graph this client probed to the evidence directory as JSON.

        The full WorkerResult, not the truncated node/topic lists a failing
        assertion prints: this is the evidence of what an unauthenticated probe
        could enumerate, kept whether the leaf passed or failed.
        """
        if not self._graph_cache:
            return ()
        into.mkdir(parents=True, exist_ok=True)
        written = []
        for key, result in self._graph_cache.items():
            path = into / f"graph-{key.replace(':', '-')}.json"
            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
            written.append(path)
        return tuple(written)
