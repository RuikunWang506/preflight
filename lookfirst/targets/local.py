"""A folder on this computer: read in place, never copied, changed or run."""

from __future__ import annotations

from pathlib import Path

from lookfirst.core.errors import TargetError
from lookfirst.core.textsafe import one_line
from lookfirst.targets.models import ResolvedTarget, TargetSpec
from lookfirst.targets.oneliner import looks_like_command

_EXPLICIT_PREFIXES = ("/", "./", "../", "~")


def parse_local(raw: str, cwd: Path) -> TargetSpec | None:
    """A folder if raw names one that exists, or clearly means a path. Otherwise None."""
    explicit = raw.startswith(_EXPLICIT_PREFIXES) or raw in (".", "..")
    try:
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        exists = candidate.exists()
    except (OSError, RuntimeError, ValueError):  # name too long, unknown ~user, and so on
        exists = False
    if exists:
        if not candidate.is_dir():
            raise TargetError(
                f"{one_line(raw, 120)} is a file. "
                "lookfirst checks folders, repos, commands and packages.",
                hint="To check a script, point lookfirst at the folder it's in.",
            )
        return TargetSpec(kind="local", raw=raw, path=candidate.resolve())
    if explicit and not looks_like_command(raw):  # "./install.sh --yes" is a command, not a folder
        raise TargetError(f"Couldn't find the folder {one_line(raw, 120)}.")
    return None


def resolve_local(spec: TargetSpec) -> ResolvedTarget:
    if spec.path is None or not spec.path.is_dir():
        raise TargetError(f"Couldn't find the folder {one_line(spec.raw, 120)}.")
    return ResolvedTarget(spec=spec, root=spec.path, resolved=str(spec.path))
