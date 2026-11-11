"""Plain-English wording shared by the terminal and Markdown outputs."""

from __future__ import annotations

from typing import Literal

from lookfirst.core.textsafe import one_line
from lookfirst.verdict.schema import (
    Evidence,
    Finding,
    Report,
    SandboxRun,
    Severity,
    Target,
    VerdictLabel,
)

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


def is_serious(finding: Finding) -> bool:
    """Critical and high findings get every detail; the rest are worth knowing."""
    return finding.severity in (Severity.critical, Severity.high)


def evidence_place(ev: Evidence) -> str:
    """Where a piece of evidence points, in a few words."""
    return one_line(ev.ref, 120) + (f" line {ev.line}" if ev.line else "")


def where_short(finding: Finding) -> str:
    """The first place a finding points to, and how many more there are."""
    if not finding.evidence:
        return ""
    ev = finding.evidence[0]
    more = len(finding.evidence) - 1 + sum(int(e.data.get("more", 0)) for e in finding.evidence)
    if "package" in ev.data:  # findings about package versions: name the first (the worst)
        name = one_line(f"{ev.data['package']} {ev.data.get('version', '')}".strip(), 80)
        if isinstance(ev.data.get("worst"), int | float):
            return f"Worst: {name} (score {ev.data['worst']:g}), in {evidence_place(ev)}"
        first = f"{name}, in {evidence_place(ev)}"
        return f"{first}, and {more} more" if more else first
    first = evidence_place(ev)
    return f"{first} and {more} more" if more else first


SANDBOX_LIMITS = (
    "It's a Linux container, so macOS-only tricks, such as fake password dialogs, don't run "
    "there. Malware can also wait, or notice the sandbox: seeing nothing doesn't mean it's safe."
)
_NETWORK_MODES = {
    "sinkhole": "registries and its own sites passed; the sandbox answered every other request",
    "passthrough": "every request was recorded and let through (--network passthrough)",
    "offline": "no network at all (--network offline)",
}


def describe_sandbox(run: SandboxRun) -> list[tuple[str, str]]:
    """The dry run's rows: what ran, its network, how long, what it touched, its limits."""
    lines = run.command.splitlines() or [""]
    command = one_line(lines[0], 120)
    if len(lines) > 1:
        command += f" (and {len(lines) - 1} more line{'s' if len(lines) > 2 else ''})"
    ran = f"{command}: {one_line(run.why, 100)}" if run.why else command
    time = f"{run.duration_s:.1f} s"
    if run.timed_out:
        time += ", stopped at the time limit"
    elif run.exit_code == 0:
        time += ", finished normally"
    elif run.exit_code is not None:
        time += f", exited with code {run.exit_code}"
    if run.arch == "amd64":
        time += ", as amd64"
    files = f"{run.files_changed} file{'' if run.files_changed == 1 else 's'} changed"
    if run.hosts:
        shown = ", ".join(one_line(h, 60) for h in run.hosts[:5])
        extra = len(run.hosts) - 5
        files += f"; contacted {shown}" + (f" and {extra} more" if extra > 0 else "")
    else:
        files += "; contacted no sites"
    return [
        ("Ran", ran),
        ("Network", _NETWORK_MODES.get(run.network, run.network)),
        ("Time", time),
        ("Touched", files),
        ("Limits", SANDBOX_LIMITS),
    ]


def describe_tools(report: Report) -> str | None:
    """Which outside scanners ran, and what they sent where."""
    parts = []
    for tool in report.tools:
        if tool.status not in ("ran", "nothing_to_scan"):
            continue
        name = one_line(f"{tool.name} {tool.version}" if tool.version else tool.name, 60)
        parts.append(f"{name}, which {one_line(tool.detail, 120)}" if tool.detail else name)
    if not parts:
        return None
    return "Also checked with " + " and ".join(parts) + "."


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
    if isinstance(d.get("files"), int) and d["files"] > 1:
        notes.append(f"Pinned in {d['files']} lockfiles")
    if "more" in d:
        notes.append(f"…and {d['more']} more like this")
    if isinstance(d.get("elsewhere"), int) and d["elsewhere"]:
        n = d["elsewhere"]
        notes.append(f"Also {n} in tests, examples and dev scripts, not listed")
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


def describe_identity(report: Report) -> list[Segment] | None:
    """One line on whether this is the real project, or None if that wasn't checked."""
    identity = report.identity
    if identity is None:
        return None
    original = one_line(identity.original or "", 140)
    if identity.status == "original":
        return [("text", "the original project")]
    if identity.status == "fork_benign":
        return [("text", "a fork of "), ("name", original)]
    if identity.status == "likely_impersonation":
        sure = round(identity.confidence * 100)
        return [("text", "looks like a copy of "), ("name", original), ("text", f" ({sure}% sure)")]
    return [("text", "not a copy of a project lookfirst knows")]
