"""The Markdown report (`--report FILE`): shareable, with the same wording as the terminal,
every detail, and links to the evidence.

- Files in a GitHub repo link to that exact commit, so the link shows what was checked.
- Advisories link to osv.dev. Other web addresses link only if they're http or https.
- Everything from a target is escaped, so it can't add its own links, images or HTML.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from urllib.parse import quote

from lookfirst.core.textsafe import one_line
from lookfirst.core.urls import split_url
from lookfirst.verdict.describe import (
    SKELETON_NOTE,
    Segment,
    describe_identity,
    describe_target,
    describe_tools,
    evidence_notes,
    headline_text,
    is_serious,
)
from lookfirst.verdict.schema import VERDICT_TEXT, Evidence, Finding, Report, VerdictLabel

# Characters that can create emphasis, code, links, images, HTML, table cells
# or strikethrough mid-line. Every line we write starts with our own text, so
# line-start syntax (headings, lists) can't be triggered from inside.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")
_ADVISORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_TABLE_RULES = (
    "package.known_vulnerabilities",
    "package.known_vulnerabilities_elsewhere",
)


def md_text(text: str, limit: int | None = 200) -> str:
    """Untrusted text as plain Markdown text: syntax escaped, then hidden characters shown."""
    # Escape first, so the <U+XXXX> marks added by one_line stay readable.
    return one_line(_MD_SPECIAL.sub(r"\\\1", text), limit)


def md_code(text: str, limit: int | None = 200) -> str:
    """Untrusted text as an inline code span that it can't break out of."""
    safe = one_line(text, limit).replace("|", "\\|")  # a bare | would split a table cell
    longest = max((len(run) for run in re.findall(r"`+", safe)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if safe.startswith("`") or safe.endswith("`") else ""
    return f"{fence}{pad}{safe}{pad}{fence}"


def md_link(text: str, url: str) -> str:
    """A link whose address can't break out: only http(s), percent-encoded, in <...>."""
    parts = split_url(url)
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        return text
    safe = quote(one_line(url, 2048), safe=":/?#@!$&'*+,;=%~-._")
    return f"[{text}](<{safe}>)"


def _segments(segments: list[Segment]) -> str:
    # Name segments were already made one-line safe; md_code adds Markdown safety.
    return "".join(md_code(value, None) if kind == "name" else value for kind, value in segments)


def _commit(report: Report) -> tuple[str, str] | None:
    """(owner/repo, sha) when the target is a GitHub repo at a known commit."""
    if report.target.kind != "github" or not report.target.resolved:
        return None
    repo, _, sha = report.target.resolved.rpartition("@")
    return (repo, sha) if _REPO.match(repo) and _SHA.match(sha) else None


def _place(ev: Evidence, commit: tuple[str, str] | None) -> str:
    where = md_code(ev.ref) + (f" line {ev.line}" if ev.line else "")
    if ev.type == "url":
        return md_link(where, ev.ref)
    path = PurePosixPath(ev.ref)
    if ev.type == "file" and commit and not path.is_absolute() and ".." not in path.parts:
        repo, sha = commit
        url = f"https://github.com/{repo}/blob/{sha}/{quote(ev.ref)}"
        return md_link(where, url + (f"#L{ev.line}" if ev.line else ""))
    return where


def _advisories(value: object) -> str:
    links = []
    for item in str(value).replace("…", "").split(","):
        advisory = item.strip()
        if _ADVISORY.match(advisory):
            links.append(md_link(md_code(advisory), f"https://osv.dev/vulnerability/{advisory}"))
    return ", ".join(links) + (" …" if "…" in str(value) else "")


def _package_table(f: Finding, commit: tuple[str, str] | None) -> list[str]:
    lines = [
        "| Package | Version | Worst score | Fixed in | Advisories | Where |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    more = 0
    for ev in f.evidence:
        d = ev.data
        worst = f"{d['worst']:g}" if isinstance(d.get("worst"), int | float) else ""
        files = d.get("files")
        where = _place(ev, commit) + (
            f" and {files - 1} more" if isinstance(files, int) and files > 1 else ""
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    md_code(str(d.get("package", ""))),
                    md_code(str(d.get("version", ""))),
                    worst,
                    md_code(str(d["fixed"])) if d.get("fixed") else "",
                    _advisories(d.get("advisories", "")),
                    where,
                ]
            )
            + " |"
        )
        more += int(d.get("more", 0))
    if more:
        lines += ["", f"…and {more} more package versions."]
    return lines


def _finding(f: Finding, commit: tuple[str, str] | None) -> list[str]:
    lines = [f"### {f.severity.value.upper()}: {md_text(f.title)}", ""]
    lines += [
        md_text(f.explanation, None),
        "",
        f"**What to do:** {md_text(f.recommendation, None)}",
        "",
    ]
    if f.id in _TABLE_RULES:
        lines += _package_table(f, commit)
        lines.append("")
    else:
        for ev in f.evidence:
            lines.append(f"- Evidence: {_place(ev, commit)}")
            if ev.excerpt:
                lines.append(f"  - Quoted: {md_code(ev.excerpt)}")
            for note in evidence_notes(ev):
                lines.append(f"  - {md_text(note, None)}")
            if ev.data.get("advisories") and ev.type != "url":
                lines.append(f"  - Advisory: {_advisories(ev.data['advisories'])}")
    if f.source != "lookfirst":
        version = f" {f.source_version}" if f.source_version else ""
        lines.append(f"- Found by {md_text(f.source + version)}")
    lines.append("")
    return lines


def render_markdown(report: Report) -> str:
    verdict = VERDICT_TEXT[report.verdict]
    commit = _commit(report)
    lines = [
        f"# lookfirst report: {verdict}",
        "",
        f"**{verdict}: {headline_text(report)}**",
        "",
    ]
    if not report.checked:
        lines += [f"> {SKELETON_NOTE}", ""]
    if report.summary:
        lines += ["Top reasons:", ""]
        lines += [f"{i}. {md_text(reason)}" for i, reason in enumerate(report.summary, start=1)]
        lines.append("")

    when = report.generated_at.strftime("%Y-%m-%d %H:%M %Z").strip()
    lines += ["| | |", "| --- | --- |", f"| Target | {_segments(describe_target(report.target))} |"]
    identity = describe_identity(report)
    if identity is not None:
        lines.append(f"| Identity | {_segments(identity)} |")
    if report.target.source_repo:
        lines.append(
            f"| Source repo | {md_code(report.target.source_repo)} (declared by the package) |"
        )
    lines += [f"| Checked | {when} with lookfirst {md_text(report.tool_version)} |", ""]

    serious = [f for f in report.findings if is_serious(f)]
    minor = [f for f in report.findings if not is_serious(f)]
    if serious:
        lines += ["## Details", ""]
        for f in serious:
            lines += _finding(f, commit)
    if minor:
        header = "Worth knowing" if report.verdict is VerdictLabel.looks_ok else "Also found"
        lines += [f"## {header}", ""]
        for f in minor:
            lines += _finding(f, commit)

    if report.not_checked:
        lines += ["## Not checked", ""]
        for item in report.not_checked:
            how = f" ({md_text(item.how_to_enable)})" if item.how_to_enable else ""
            lines.append(f"- **{md_text(item.what)}**: {md_text(item.reason)}{how}")
        lines.append("")

    tools = describe_tools(report)
    if tools:
        lines += [md_text(tools, None), ""]

    lines += ["---", "", f"*{md_text(report.disclaimer, None)}*", ""]
    return "\n".join(lines)
