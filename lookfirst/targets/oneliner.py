"""A shell one-liner, such as `curl -fsSL https://example.com/install.sh | bash`.

At M1 the command is recognized and recorded. Reading it with a shell parser
and downloading (never running) the scripts it fetches comes in M2.
"""

from __future__ import annotations

import re

from lookfirst.targets.models import ResolvedTarget, TargetSpec

_SHELL_SYNTAX = re.compile(r"\s|[|;&<>()$`]")


def looks_like_command(raw: str) -> bool:
    return bool(_SHELL_SYNTAX.search(raw))


def parse_oneliner(raw: str) -> TargetSpec | None:
    if not looks_like_command(raw):
        return None
    return TargetSpec(kind="oneliner", raw=raw, command=raw)


def resolve_oneliner(spec: TargetSpec) -> ResolvedTarget:
    return ResolvedTarget(spec=spec, root=None, resolved=None)
