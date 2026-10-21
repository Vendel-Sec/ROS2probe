# Options and the log hook live at the root so pytest loads them before it reads either.

import datetime as dt
from pathlib import Path

import pytest
import yaml

DEFAULT_PROFILE = Path(__file__).parent / "targets" / "sim-lab.yaml"


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """A directory per target, and one per run inside it.

    pytest's log_file is one fixed path, so without this each run overwrites the
    last one's evidence. tryfirst, because the logging plugin reads the option
    when it is configured.
    """
    if config.option.collectonly:
        config.option.log_file = ""       # a listing is not a run, and leaves no file
        return
    default = Path(config.getini("log_file"))
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = _target_name(Path(config.option.target).expanduser())
    config.option.log_file = str(default.parent / target / stamp / default.name)


def _target_name(path: Path) -> str:
    """The profile's name, or its file stem when the profile cannot be read here."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return path.stem
    name = raw.get("name") if isinstance(raw, dict) else None
    return Path(str(name)).name if name else path.stem


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("ros2probe")
    group.addoption(
        "--target", action="store", default=str(DEFAULT_PROFILE),
        help="target profile YAML (default: targets/sim-lab.yaml)",
    )
    group.addoption(
        "--arm", action="store_true", default=False,
        help="allow intrusive tests to write to the target",
    )
    group.addoption(
        "--allow-actuation-payload", action="store_true", default=False,
        help="with --arm, publish one message on an actuation topic: ros.payloads, or zero",
    )
