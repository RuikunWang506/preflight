"""The Claude Code plugin in plugin/ and the marketplace file that lists it.

`claude plugin validate plugin` and `claude plugin validate .` are the full checks (run
by hand: CI has no Claude Code). These tests keep the pieces consistent with each other
and with lookfirst, and check the launcher script, which is lookfirst's own code.
"""

from __future__ import annotations

import json
import os
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent
PLUGIN = ROOT / "plugin"
LAUNCHER = PLUGIN / "scripts" / "run-lookfirst"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_the_plugin_version_matches_lookfirst() -> None:
    manifest = load(PLUGIN / ".claude-plugin" / "plugin.json")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert manifest["name"] == "lookfirst"
    assert manifest["version"] == project["version"]
    assert manifest["license"] == project["license"]


def test_the_marketplace_lists_the_plugin() -> None:
    market = load(ROOT / ".claude-plugin" / "marketplace.json")
    (entry,) = market["plugins"]
    assert (market["name"], entry["name"], entry["source"]) == (
        "lookfirst",
        "lookfirst",
        "./plugin",
    )
    assert (ROOT / entry["source"] / ".claude-plugin" / "plugin.json").is_file()


def test_the_hook_runs_lookfirst_hook_before_bash_commands_with_time_to_spare() -> None:
    hooks = load(PLUGIN / "hooks" / "hooks.json")["hooks"]
    (entry,) = hooks["PreToolUse"]
    (hook,) = entry["hooks"]
    assert entry["matcher"] == "Bash"
    assert hook["type"] == "command"
    assert hook["command"] == 'sh "${CLAUDE_PLUGIN_ROOT}/scripts/run-lookfirst" hook'
    assert hook["timeout"] == 30  # lookfirst's own budget is 20 seconds, so it answers first


def test_the_mcp_server_runs_lookfirst_mcp() -> None:
    servers = load(PLUGIN / ".mcp.json")["mcpServers"]
    assert servers == {
        "lookfirst": {
            "command": "sh",
            "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/run-lookfirst", "mcp"],
        }
    }


def test_the_skill_says_when_to_check_and_how_to_act() -> None:
    text = (PLUGIN / "skills" / "lookfirst" / "SKILL.md").read_text()
    front, _, body = text.removeprefix("---\n").partition("\n---\n")
    fields = dict(line.split(": ", 1) for line in front.splitlines())
    assert fields["name"] == "lookfirst"
    assert len(fields["description"]) <= 1024
    for words in (
        "lookfirst_check",
        "quoted_from_target",
        "**Don't run:**",
        "**Caution:**",
        "**Looks OK:**",
    ):
        assert words in body


def test_the_plugin_has_no_bin_folder() -> None:
    """Claude Cowork and claude.ai don't install plugins that ship executables in bin/."""
    assert not (PLUGIN / "bin").exists()


def run_launcher(tmp_path: Path, *args: str, path: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": path,
        "HOME": str(tmp_path / "home"),
        "CLAUDE_PLUGIN_DATA": str(tmp_path / "data"),
    }
    return subprocess.run(  # noqa: S603 - the plugin's own launcher, not a fixture
        ["/bin/sh", str(LAUNCHER), *args],
        input="{}",
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )


def test_without_lookfirst_commands_go_ahead_with_a_daily_reminder(tmp_path: Path) -> None:
    if any(Path(p, "lookfirst").exists() for p in ("/opt/homebrew/bin", "/usr/local/bin")):
        return  # installed system-wide here: the launcher would find it
    first = run_launcher(tmp_path, "hook", path="/usr/bin:/bin")
    assert first.returncode == 0
    assert json.loads(first.stdout) == {
        "systemMessage": "lookfirst isn't installed, so this plugin can't check commands yet. "
        "Install it with: uv tool install lookfirst"
    }
    again = run_launcher(tmp_path, "hook", path="/usr/bin:/bin")
    assert (again.returncode, again.stdout) == (0, "")
    server = run_launcher(tmp_path, "mcp", path="/usr/bin:/bin")
    assert server.returncode == 1
    assert "uv tool install lookfirst" in server.stderr


def test_the_launcher_finds_lookfirst_where_uv_puts_it(tmp_path: Path) -> None:
    fake = tmp_path / "home" / ".local" / "bin" / "lookfirst"
    fake.parent.mkdir(parents=True)
    fake.write_text('#!/bin/sh\necho "lookfirst was given: $*"\n')
    fake.chmod(0o755)
    done = run_launcher(tmp_path, "hook", path="/usr/bin:/bin")
    assert (done.returncode, done.stdout) == (0, "lookfirst was given: hook\n")


def test_lookfirst_on_path_comes_first(tmp_path: Path) -> None:
    on_path = tmp_path / "somewhere"
    on_path.mkdir()
    fake = on_path / "lookfirst"
    fake.write_text('#!/bin/sh\necho "from PATH: $*"\n')
    fake.chmod(0o755)
    done = run_launcher(tmp_path, "mcp", path=f"{on_path}:/usr/bin:/bin")
    assert (done.returncode, done.stdout) == (0, "from PATH: mcp\n")


def test_the_launcher_is_executable_and_posix_sh() -> None:
    assert LAUNCHER.read_text().startswith("#!/bin/sh\n")
    assert os.access(LAUNCHER, os.X_OK)
