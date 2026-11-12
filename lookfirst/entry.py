"""The `lookfirst` command's entry point.

`lookfirst hook` runs before every shell command a coding agent runs, so it has to start
fast. It's handed off here, before anything outside the Python standard library is
imported (SPEC section 10). Every other command goes to the full interface in cli.py,
which loads Typer, rich and pydantic.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["hook"]:
        from lookfirst.hook import main as hook_main

        return hook_main(args[1:])
    from lookfirst.cli import main as cli_main

    return cli_main(args)
