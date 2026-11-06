"""Plain-English wording shared by the terminal and Markdown outputs."""

from __future__ import annotations

from typing import Literal

from lookfirst.core.textsafe import one_line
from lookfirst.verdict.schema import Evidence, Report, Target, VerdictLabel

HEADLINES: dict[VerdictLabel, str] = {
    VerdictLabel.looks_ok: "no warning signs found in what was checked.",
    VerdictLabel.caution: "we found warning signs. Read them before you run it.",
    VerdictLabel.dont_run: "we found serious warning signs.",
}

# Shown only if no check ran at all. Since M2 that can't happen for a successful check:
# a run where the main content couldn't be read is an error instead (skeleton decision 3).
SKELETON_NOTE = "Skeleton build: no checks exist yet, so nothing was checked."


def headline_text(report: Report) -> str:
    """The words after the verdict. Looks OK says how many minor findings follow."""
    if report.verdict is VerdictLabel.looks_ok and report.findings:
        n = len(report.findings)
        return (
            f"no serious warning signs. {n} {'thing' if n == 1 else 'things'} worth knowing below."
        )
    return HEADLINES[report.verdict]


def evidence_notes(ev: Evidence) -> list[str]:
    """Plain-English notes for the extra facts on a piece of evidence. Values are untrusted
    and are made one-line safe here; renderers add their own escaping on top."""
    d = ev.data
    notes = []
    if "where" in d:
        notes.append(f"Hidden in {one_line(str(d['where']), 80)}")
    if "what" in d:
        notes.append(one_line(str(d["what"]), 200))
    if "installer" in d:
        text = f"Installer: {one_line(str(d['installer']), 60)}"
        if d.get("matches_last_seen") is True:
            text += ", the same copy lookfirst last saw"
        elif d.get("matches_last_seen") is False:
            seen = one_line(str(d.get("last_seen", "earlier")), 20)
            text += f", changed since lookfirst last saw it ({seen})"
        notes.append(text)
    if "reason" in d:
        notes.append(f"Couldn't read it: {one_line(str(d['reason']), 160)}")
    if "lines" in d and "-" in str(d["lines"]):  # a single line is already in "line N"
        notes.append(f"Lines {one_line(str(d['lines']), 20)}")
    if "runs" in d:
        notes.append(f"Runs {one_line(str(d['runs']), 160)}")
    if "more" in d:
        notes.append(f"…and {d['more']} more like this")
    return notes


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
        # What the user typed is shortest and most familiar; the full path is in the JSON.
        shown = raw if len(raw) <= 80 else (resolved or raw)
        return [("name", one_line(shown, 160)), ("text", " (folder on this computer)")]
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
