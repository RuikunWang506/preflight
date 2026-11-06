"""The Markdown report (`--report FILE`): shareable, with the same wording as the terminal."""

from __future__ import annotations

import re

from lookfirst.core.textsafe import one_line
from lookfirst.verdict.describe import HEADLINES, SKELETON_NOTE, Segment, describe_target
from lookfirst.verdict.schema import VERDICT_TEXT, Report

# Characters that can create emphasis, code, links, images, HTML, table cells
# or strikethrough mid-line. Every line we write starts with our own text, so
# line-start syntax (headings, lists) can't be triggered from inside.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")


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


def _segments(segments: list[Segment]) -> str:
    # Name segments were already made one-line safe; md_code adds Markdown safety.
    return "".join(md_code(value, None) if kind == "name" else value for kind, value in segments)


def render_markdown(report: Report) -> str:
    verdict = VERDICT_TEXT[report.verdict]
    lines = [
        f"# lookfirst report: {verdict}",
        "",
        f"**{verdict}: {HEADLINES[report.verdict]}**",
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
    if report.target.source_repo:
        lines.append(
            f"| Source repo | {md_code(report.target.source_repo)} (declared by the package) |"
        )
    lines += [f"| Checked | {when} with lookfirst {md_text(report.tool_version)} |", ""]

    if report.findings:
        lines += ["## Details", ""]
        for f in report.findings:
            lines += [f"### {f.severity.value.upper()}: {md_text(f.title)}", ""]
            lines += [
                md_text(f.explanation, None),
                "",
                f"**What to do:** {md_text(f.recommendation, None)}",
                "",
            ]
            for ev in f.evidence:
                where = md_code(ev.ref) + (f" line {ev.line}" if ev.line else "")
                lines.append(f"- Evidence: {where}")
                if ev.excerpt:
                    lines.append(f"  - Quoted: {md_code(ev.excerpt)}")
            if f.source != "lookfirst":
                version = f" {f.source_version}" if f.source_version else ""
                lines.append(f"- Found by {md_text(f.source + version)}")
            lines.append("")

    if report.not_checked:
        lines += ["## Not checked", ""]
        for item in report.not_checked:
            how = f" ({md_text(item.how_to_enable)})" if item.how_to_enable else ""
            lines.append(f"- **{md_text(item.what)}**: {md_text(item.reason)}{how}")
        lines.append("")

    lines += ["---", "", f"*{md_text(report.disclaimer, None)}*", ""]
    return "\n".join(lines)
