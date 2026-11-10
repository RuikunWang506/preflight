"""Running an outside scanner safely.

- Found on PATH, or where they're usually installed (the Claude Code hook can run with a
  short PATH).
- Run without a shell, with no input, a time limit and a cap on how much output is read.
- Given only the environment they need. GitHub tokens, and anything else that might be
  a secret, stay out.
- Their output is untrusted text, like everything else lookfirst reads.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import cache
from pathlib import Path

TIME_LIMIT = 120  # seconds, for each run
MAX_OUTPUT = 128 * 1024 * 1024  # osv-scanner's JSON for a big monorepo runs to tens of MB
_STDERR_TAIL = 1024 * 1024  # progress lines; osv-scanner says there how many packages it sent
# Where tools are usually installed, besides PATH.
_EXTRA_DIRS = (Path.home() / ".local" / "bin", Path("/opt/homebrew/bin"), Path("/usr/local/bin"))
# The only environment variables a tool gets.
_KEEP_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TZ",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)
_VERSION = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


class ToolFailed(Exception):
    """The tool couldn't do its job. The message says why, in plain English."""


@dataclass(frozen=True)
class ToolOutput:
    returncode: int
    stdout: str
    stderr: str  # up to the last MB


def locate(name: str) -> Path | None:
    """Where the tool is installed, or None if it isn't."""
    return find_tool(name, _EXTRA_DIRS)


def find_tool(name: str, extra_dirs: tuple[Path, ...]) -> Path | None:
    found = shutil.which(name)
    if found:
        return Path(found)
    for folder in extra_dirs:
        candidate = folder / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def tool_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _KEEP_ENV}
    parts = [p for p in env.get("PATH", "").split(os.pathsep) if p]
    parts += [str(d) for d in _EXTRA_DIRS if str(d) not in parts]
    env["PATH"] = os.pathsep.join(parts)
    return env


def run_tool(
    executable: Path, args: list[str], *, timeout: int = TIME_LIMIT, cwd: Path | None = None
) -> ToolOutput:
    """Run the tool and return what it printed. Raises ToolFailed if it couldn't finish."""
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(  # noqa: S603 - a scanner the user installed, list args, no shell
                [str(executable), *args],
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=tool_env(),
                cwd=cwd,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolFailed(f"didn't finish within {_duration(timeout)}") from exc
        except OSError as exc:
            raise ToolFailed(f"it couldn't be started ({exc.strerror or exc})") from exc
        if os.fstat(out.fileno()).st_size > MAX_OUTPUT:
            raise ToolFailed("its output was too large to read")
        out.seek(0)
        stdout = out.read().decode("utf-8", "replace")
        size = os.fstat(err.fileno()).st_size
        err.seek(max(0, size - _STDERR_TAIL))
        stderr = err.read().decode("utf-8", "replace")
    return ToolOutput(proc.returncode, stdout, stderr)


@cache
def tool_version(executable: Path) -> str | None:
    """The tool's version number, from `--version`."""
    try:
        output = run_tool(executable, ["--version"], timeout=30)
    except ToolFailed:
        return None
    m = _VERSION.search(output.stdout or output.stderr)
    return m.group(1) if m else None


def _duration(seconds: int) -> str:
    if seconds >= 120 and seconds % 60 == 0:
        return f"{seconds // 60} minutes"
    return f"{seconds} second{'' if seconds == 1 else 's'}"


def last_line(text: str) -> str:
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""
