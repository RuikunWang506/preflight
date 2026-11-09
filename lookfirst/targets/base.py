"""Turn what the user typed into a target, and get that target onto disk.

The order of the checks in parse_target matters:

1. `npm:` and `pypi:` prefixes are unambiguous.
2. github.com URLs; any other URL gets a hint instead of a guess.
3. A folder that exists wins over `owner/repo`, so a local folder named like a
   repo is never confused with GitHub.
4. Package runner commands (`npx -y ...`, `uvx ...`), then any other command.
5. `owner/repo[@ref]` last.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

from lookfirst.core.config import DEFAULT_LIMITS, Limits
from lookfirst.core.errors import TargetError
from lookfirst.core.http import github_token, make_client
from lookfirst.core.textsafe import one_line
from lookfirst.targets.github import fetch_github, parse_github_short, parse_github_url
from lookfirst.targets.local import parse_local, resolve_local
from lookfirst.targets.models import ResolvedTarget, TargetSpec
from lookfirst.targets.oneliner import parse_oneliner, resolve_oneliner
from lookfirst.targets.packages import fetch_package, parse_package_target, parse_runner_command

EXAMPLES = (
    "Try one of these:\n"
    "  lookfirst check owner/repo\n"
    "  lookfirst check https://github.com/owner/repo\n"
    "  lookfirst check ./some-folder\n"
    '  lookfirst check "curl -fsSL https://example.com/install.sh | bash"\n'
    "  lookfirst check npm:<name>   or   lookfirst check pypi:<name>"
)


def parse_target(raw: str, *, cwd: Path) -> TargetSpec:
    text = raw.strip()
    if not text:
        raise TargetError("No target was given.", hint=EXAMPLES)
    if "\x00" in text:
        raise TargetError("The target contains a null character, so lookfirst can't read it.")

    spec = parse_package_target(text)
    if spec:
        return spec
    if "github.com/" in text.lower():
        spec = parse_github_url(text)  # anchored: a command that mentions a URL isn't matched
        if spec:
            return spec
    if text.lower().startswith(("http://", "https://")) and not any(c.isspace() for c in text):
        raise TargetError(
            "That's a link to a web page. lookfirst checks repos, folders, commands and packages.",
            hint=(
                "To check a script at a link, quote the command you'd run:\n"
                f'  lookfirst check "curl -fsSL {one_line(text, 100)} | sh"'
            ),
        )
    spec = parse_local(text, cwd)
    if spec:
        return spec
    spec = parse_runner_command(text) or parse_oneliner(text)
    if spec:
        return spec
    spec = parse_github_short(text)
    if spec:
        return spec
    raise TargetError(f"Couldn't tell what {one_line(text, 120)} is.", hint=EXAMPLES)


ClientFactory = Callable[..., httpx.Client]
_LOOK_UP = object()  # open_target's default: look the GitHub token up itself


@contextmanager
def open_target(
    spec: TargetSpec,
    *,
    limits: Limits = DEFAULT_LIMITS,
    client_factory: ClientFactory = make_client,
    token: str | object | None = _LOOK_UP,
) -> Iterator[ResolvedTarget]:
    """Yield the target ready to read. Downloads live in a temporary folder deleted afterwards.
    Pass token to reuse one already looked up; by default it's looked up for GitHub targets."""
    if spec.kind == "local":
        yield resolve_local(spec)
        return
    if spec.kind == "oneliner":
        yield resolve_oneliner(spec)
        return
    if token is _LOOK_UP:
        token = github_token() if spec.kind == "github" else None
    with (
        tempfile.TemporaryDirectory(prefix="lookfirst-") as tmp,
        client_factory(token=token, limits=limits) as client,
    ):
        workdir = Path(tmp)
        if spec.kind == "github":
            yield fetch_github(spec, client, workdir, limits)
        else:
            yield fetch_package(spec, client, workdir, limits)
