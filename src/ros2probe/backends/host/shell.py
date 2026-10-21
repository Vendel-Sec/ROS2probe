import logging
import shlex
import subprocess

from pydantic import BaseModel, ConfigDict, Field

from ...targets.profile import Robot, Ssh, Transport

LOG = logging.getLogger(__name__)

COMMAND_TIMEOUT_S = 20.0

# Exit codes and messages a shell uses for a program that is not there. 126 is
# "found but not executable", 127 is "not found".
_MISSING_SIGNATURES: tuple[str, ...] = (
    "command not found",
    "no such file or directory",
)
# ssh's own exit code: it failed to connect or authenticate, the command never ran.
SSH_FAILED = 255

class CommandResult(BaseModel):
    """One command's outcome."""
    model_config = ConfigDict(frozen=True)

    command: str
    ran: bool
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.ran and self.exit_code == 0

    @property
    def out(self) -> str:
        return self.stdout.strip()

    @property
    def lines(self) -> list[str]:
        return [line for line in self.stdout.splitlines() if line.strip()]

    def contains(self, needle: str) -> bool:
        return needle.lower() in self.stdout.lower()

    def __str__(self) -> str:
        output = (self.stdout + self.stderr).strip() or self.error or "<no output>"
        return f"$ {self.command}  (exit {self.exit_code})\n{output}"


class FileMode(BaseModel):
    """`stat` output for one path on the target."""
    model_config = ConfigDict(frozen=True)

    path: str
    exists: bool
    mode: str = ""          # four octal digits
    owner: str = ""
    group: str = ""
    kind: str = ""          # "directory" | "regular file" | ...

    @property
    def mode_int(self) -> int:
        try:
            return int(self.mode, 8)
        except ValueError:
            return 0

    @property
    def group_writable(self) -> bool:
        return bool(self.mode_int & 0o020)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode_int & 0o002)

    @property
    def world_readable(self) -> bool:
        return bool(self.mode_int & 0o004)

    @property
    def group_readable(self) -> bool:
        return bool(self.mode_int & 0o040)

    def writable_by(self, user: str) -> bool:
        return self.owner == user or self.group_writable or self.world_writable


def _program_missing(result: CommandResult, program: str) -> bool:
    blob = (result.stdout + result.stderr).lower()
    # sudo resolves the program itself, and says so with exit 1, not 127.
    if result.exit_code == 1 and f"sudo: {program.lower()}: command not found" in blob:
        return True
    if result.exit_code not in (126, 127):
        return False
    return any(sig in blob for sig in _MISSING_SIGNATURES)


class HostShell(BaseModel):
    """The `host` fixture: commands on the robot, over ssh."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    robot: Robot
    # Commands are cached for the session: a branch B run asks the same handful of
    # questions from several tests, and each one is an SSH round trip.
    cache: dict[str, CommandResult] = Field(default_factory=dict, exclude=True)

    @property
    def ssh(self) -> Ssh:
        if self.robot.transport is not Transport.SSH or self.robot.ssh is None:
            raise ValueError("robot.ssh not set")
        return self.robot.ssh

    @property
    def position(self) -> str:
        user = f"{self.ssh.user}@" if self.ssh.user else ""
        return f"ssh {user}{self.robot.address}:{self.ssh.port}" + (" + sudo" if self.ssh.sudo else "")

    # --- command execution -------------------------------------------------- #

    def _ssh(self, command: str) -> list[str]:
        s = self.ssh
        ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(s.port)]
        if s.known_hosts:
            ssh += ["-o", f"UserKnownHostsFile={s.known_hosts}", "-o", "StrictHostKeyChecking=yes"]
        else:
            ssh += ["-o", "StrictHostKeyChecking=accept-new"]
        if s.identity:
            ssh += ["-i", str(s.identity), "-o", "IdentitiesOnly=yes"]
        target = f"{s.user}@{self.robot.address}" if s.user else self.robot.address
        return [*ssh, target, command]

    def run(self, *argv: str, elevate: bool = True) -> CommandResult:
        """Run one allowlisted command. Results are cached per session.

        With `ssh.sudo`, the command runs through `sudo -n` unless `elevate` is
        False, for the leaves about what the login account itself can do.
        """
        # sudo is not in the allowlist because tests never name it: the profile
        # adds it, and the evidence shows the command as it ran.
        if elevate and self.ssh.sudo:
            argv = ("sudo", "-n", *argv)
        key = shlex.join(argv)
        if key in self.cache:
            return self.cache[key]

        program = argv[2] if argv[:2] == ("sudo", "-n") and len(argv) > 2 else argv[0]
        wrapped = self._ssh(key)
        try:
            proc = subprocess.run(
                wrapped, capture_output=True, text=True,
                timeout=COMMAND_TIMEOUT_S, check=False,
            )
            result = CommandResult(
                command=key, ran=True, exit_code=proc.returncode,
                stdout=proc.stdout, stderr=proc.stderr,
            )
            # A program that is not installed on the target did not answer the
            # question, it refused to be asked. Reporting the shell's own
            # "command not found" as the command's output turns a container
            # with no init system into a finding about auditd.
            if _program_missing(result, program):
                result = CommandResult(
                    command=key, ran=False,
                    error=f"{program} is not available on the target",
                )
            # Likewise a dropped connection: an empty answer from a command that
            # never ran would read as "nothing found".
            elif result.exit_code == SSH_FAILED:
                result = CommandResult(
                    command=key, ran=False,
                    error=f"ssh failed: {proc.stderr.strip() or 'exit 255'}",
                )
        except subprocess.TimeoutExpired:
            result = CommandResult(
                command=key, ran=False,
                error=f"timed out after {COMMAND_TIMEOUT_S}s",
            )
        except (OSError, FileNotFoundError) as exc:
            result = CommandResult(command=key, ran=False, error=str(exc))

        self.cache[key] = result
        LOG.debug("%s", result)
        return result

    # --- higher level helpers the branch B tests share ---------------------- #

    def stat_path(self, path: str) -> FileMode:
        # -L follows symlinks. sros2 links each enclave's governance.p7s at the
        # keystore-wide document, and a symlink's own mode is always 0777, which
        # reads as world-writable when the document behind it is not.
        result = self.run("stat", "-L", "-c", "%a|%U|%G|%F", path)
        if not result.ok or "|" not in result.out:
            return FileMode(path=path, exists=False)
        mode, owner, group, kind = result.out.split("|", 3)
        return FileMode(
            path=path, exists=True, mode=mode.zfill(4),
            owner=owner, group=group, kind=kind,
        )

    def read_file(self, path: str) -> CommandResult:
        return self.run("cat", path)

    def listening_sockets(self) -> CommandResult:
        """Listening TCP and UDP sockets. No -p, which would need root."""
        return self.run("ss", "-tulnH")

    def listening_ports(self) -> set[int]:
        out: set[int] = set()
        for line in self.listening_sockets().lines:
            fields = line.split()
            if len(fields) < 5:
                continue
            local = fields[4]
            _, _, port = local.rpartition(":")
            if port.isdigit():
                out.add(int(port))
        return out

    def listen_addresses(self, port: int) -> list[str]:
        """Local addresses with a socket listening on this port."""
        found = []
        for line in self.listening_sockets().lines:
            fields = line.split()
            if len(fields) >= 5 and fields[4].rpartition(":")[2] == str(port):
                found.append(fields[4].rpartition(":")[0])
        return found

    def groups_of(self, user: str) -> list[str]:
        result = self.run("id", "-nG", user)
        return result.out.split() if result.ok else []

    def ros_process_owner(self) -> str:
        """Which account the ROS launch process runs as, which is leaf B.1.0: when"""
        result = self.run("ps", "-eo", "user:32,args", "--no-headers")
        if not result.ok:
            return ""
        pattern = self.robot.ros_process_pattern
        needles = [p for p in pattern.split("|") if p]
        for line in result.lines:
            if any(n in line for n in needles):
                return line.split(None, 1)[0]
        return ""

    def ros_process_pids(self) -> list[int]:
        result = self.run("ps", "-eo", "pid=,args=")
        if not result.ok:
            return []
        needles = [p for p in self.robot.ros_process_pattern.split("|") if p]
        pids = []
        for line in result.lines:
            pid, _, args = line.strip().partition(" ")
            if pid.isdigit() and any(n in args for n in needles):
                pids.append(int(pid))
        return pids

    def realpath(self, path: str) -> str:
        if not path:
            return ""
        result = self.run("realpath", "-m", path)
        return result.out if result.ok else path

    def live_keystores(self, pids: list[int]) -> dict[int, str]:
        """ROS_SECURITY_KEYSTORE of each readable process, resolved, "" where unset."""
        found: dict[int, str] = {}
        for pid in pids:
            variables = self.process_environ(pid)
            if variables is not None:
                found[pid] = self.realpath(variables.get("ROS_SECURITY_KEYSTORE", ""))
        return found

    def process_environ(self, pid: int) -> dict[str, str] | None:
        environ = self.run("cat", f"/proc/{pid}/environ")
        if not environ.ok:
            return None
        return dict(v.partition("=")[::2] for v in environ.stdout.split("\0") if "=" in v)

    def whoami(self, elevate: bool = True) -> str:
        result = self.run("id", "-un", elevate=elevate)
        return result.out if result.ok else ""
