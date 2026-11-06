"""Plain-English wording shared by the terminal and Markdown outputs."""

from __future__ import annotations

from typing import Literal

from lookfirst.core.textsafe import one_line
from lookfirst.verdict.schema import Target, VerdictLabel

HEADLINES: dict[VerdictLabel, str] = {
    VerdictLabel.looks_ok: "no warning signs found in what was checked.",
    VerdictLabel.caution: "we found warning signs. Read them before you run it.",
    VerdictLabel.dont_run: "we found serious warning signs.",
}

# Shown while no check exists yet (M1). From M2, a run where nothing could be
# checked becomes an error instead (docs/PLAN-v0.1.md, skeleton decision 3).
SKELETON_NOTE = "Skeleton build: no checks exist yet, so nothing was checked."

# A segment is either a name taken from the target (shown emphasized, and
# already made safe with one_line) or our own connecting text.
Segment = tuple[Literal["name", "text"], str]

_ECOSYSTEM_LABEL = {"npm": "npm", "pypi": "PyPI"}


def _split_package(ecosystem: str, resolved: str) -> tuple[str, str]:
    if ecosystem == "pypi":
        name, _, version = resolved.partition("==")
    else:  # npm: the version follows the last "@"; scoped names start with "@"
        name, _, version = resolved.rpartition("@")
    return name, version


def describe_target(target: Target) -> list[Segment]:
    kind, raw, resolved = target.kind, target.raw, target.resolved
    if kind == "github" and resolved:
        name, _, sha = resolved.rpartition("@")
        return [
            ("name", one_line(name, 140)),
            ("text", " at commit "),
            ("name", one_line(sha[:7])),
            ("text", " (GitHub)"),
        ]
    if kind == "local":
        return [("name", one_line(resolved or raw, 160)), ("text", " (folder on this computer)")]
    if kind == "oneliner":
        return [("name", one_line(raw, 100)), ("text", " (shell command)")]
    if kind in ("npm", "pypi") and resolved:
        name, version = _split_package(kind, resolved)
        return [
            ("name", one_line(name, 120)),
            ("text", " "),
            ("name", one_line(version, 40)),
            ("text", f" ({_ECOSYSTEM_LABEL[kind]} package)"),
        ]
    if kind == "mcp_command" and resolved and ":" in resolved:
        ecosystem, _, rest = resolved.partition(":")
        name, version = _split_package(ecosystem, rest)
        label = _ECOSYSTEM_LABEL.get(ecosystem, ecosystem)
        return [
            ("name", one_line(raw, 70)),
            ("text", f" (runs the {label} package "),
            ("name", one_line(name, 120)),
            ("text", " "),
            ("name", one_line(version, 40)),
            ("text", ")"),
        ]
    return [("name", one_line(raw, 120))]
