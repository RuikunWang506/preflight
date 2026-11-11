"""The terminal report: verdict first, then the top reasons, then details.

Serious findings (critical and high) get every detail. The rest are folded to one title
and where it points; the Markdown report (`--report FILE`) has everything.

Every string from a target is passed to rich as a Text object, never as
markup, so text like "[link=...]" in a repo can't style or link anything.
"""

from __future__ import annotations

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from lookfirst.core.textsafe import one_line, visible
from lookfirst.verdict.describe import (
    SKELETON_NOTE,
    Segment,
    describe_identity,
    describe_sandbox,
    describe_target,
    describe_tools,
    evidence_notes,
    evidence_place,
    headline_text,
    is_serious,
    where_short,
)
from lookfirst.verdict.schema import VERDICT_TEXT, Finding, Report, Severity, VerdictLabel

_VERDICT_STYLE = {
    VerdictLabel.looks_ok: "bold green",
    VerdictLabel.caution: "bold yellow",
    VerdictLabel.dont_run: "bold red",
}
_SEVERITY_STYLE = {
    Severity.critical: "bold red",
    Severity.high: "bold yellow",
    Severity.medium: "cyan",
    Severity.info: "dim",
}
_INDENT = 2


def make_console(**kwargs: object) -> Console:
    """A console that never interprets markup, emoji codes or highlighting in our output."""
    return Console(highlight=False, emoji=False, markup=False, **kwargs)  # type: ignore[arg-type]


def _segments(segments: list[Segment]) -> Text:
    text = Text()
    for kind, value in segments:
        text.append(value, style="bold" if kind == "name" else None)
    return text


def _indented(renderable: object, level: int = 1) -> Padding:
    return Padding(renderable, (0, 0, 0, _INDENT * level), expand=False)  # type: ignore[arg-type]


def headline(report: Report) -> Text:
    return Text.assemble(
        (VERDICT_TEXT[report.verdict], _VERDICT_STYLE[report.verdict]),
        f": {headline_text(report)}",
    )


def _finding_block(finding: Finding) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column()
    badge = Text(finding.severity.value.upper(), style=_SEVERITY_STYLE[finding.severity])
    grid.add_row(badge, Text(one_line(finding.title, 120), style="bold"))
    grid.add_row("", Text(visible(finding.explanation)))
    grid.add_row("", Text.assemble(("What to do: ", "dim"), visible(finding.recommendation)))
    last_place = None
    for ev in finding.evidence:
        place = evidence_place(ev)
        if place != last_place:  # several lines from one file share one "Evidence:" line
            grid.add_row("", Text.assemble(("Evidence: ", "dim"), place))
            last_place = place
        if ev.excerpt:
            grid.add_row("", _indented(Text(f'"{one_line(ev.excerpt, 200)}"', style="dim")))
        for note in evidence_notes(ev):
            grid.add_row("", _indented(Text(note, style="dim")))
    source = finding.source + (f" {finding.source_version}" if finding.source_version else "")
    if finding.source != "lookfirst":
        grid.add_row("", Text(f"Found by {one_line(source, 60)}", style="dim"))
    return grid


def render_terminal(report: Report, console: Console) -> None:
    console.print()
    console.print(_indented(headline(report)))
    if not report.checked:
        console.print(_indented(Text(SKELETON_NOTE, style="yellow")))
    for reason in report.summary:
        console.print(_indented(Text("• " + one_line(reason, 120)), 2))

    console.print()
    facts = Table.grid(padding=(0, 4))
    facts.add_column(style="dim", no_wrap=True)
    facts.add_column()
    facts.add_row("Target", _segments(describe_target(report.target)))
    identity = describe_identity(report)
    if identity is not None:
        style = (
            "bold red"
            if report.identity and report.identity.status == "likely_impersonation"
            else None
        )
        row = _segments(identity)
        if style:
            row.stylize(style)
        facts.add_row("Identity", row)
    if report.target.source_repo:
        facts.add_row(
            "Source repo",
            Text.assemble(
                (one_line(report.target.source_repo, 120), "bold"),
                (" (declared by the package)", "dim"),
            ),
        )
    console.print(_indented(facts))

    serious = [f for f in report.findings if is_serious(f)]
    minor = [f for f in report.findings if not is_serious(f)]
    if serious:
        console.print()
        console.print(_indented(Text("Details", style="bold")))
        for finding in serious:
            console.print(_indented(_finding_block(finding), 2))
            console.print()
    if minor:
        console.print()
        # Looks OK promised "things worth knowing"; otherwise they back up the reasons above.
        header = "Worth knowing" if report.verdict is VerdictLabel.looks_ok else "Also found"
        console.print(_indented(Text(header, style="bold")))
        folded = Table.grid(padding=(0, 2))
        folded.add_column(no_wrap=True)
        folded.add_column()
        for finding in minor:
            badge = Text(finding.severity.value.upper(), style=_SEVERITY_STYLE[finding.severity])
            folded.add_row(badge, Text(one_line(finding.title, 120)))
            where = where_short(finding)
            if where:
                folded.add_row("", Text(where, style="dim"))
        console.print(_indented(folded, 2))
        console.print(_indented(Text("Add --report FILE to see every detail.", style="dim"), 2))

    if report.sandbox is not None:
        console.print()
        console.print(_indented(Text("Sandbox dry run", style="bold")))
        rows = Table.grid(padding=(0, 3))
        rows.add_column(style="dim", no_wrap=True)
        rows.add_column()
        for label, text in describe_sandbox(report.sandbox):
            rows.add_row(label, Text(text))
        console.print(_indented(rows, 2))

    if report.not_checked:
        console.print()
        console.print(_indented(Text("Not checked", style="bold")))
        skipped = Table.grid(padding=(0, 3))
        skipped.add_column(ratio=2)
        skipped.add_column(ratio=3, style="dim")
        for item in report.not_checked:
            reason = item.reason + (f" ({item.how_to_enable})" if item.how_to_enable else "")
            skipped.add_row(one_line(item.what, 60), one_line(reason, 120))
        console.print(_indented(skipped, 2))

    tools = describe_tools(report)
    if tools:
        console.print()
        console.print(_indented(Text(tools, style="dim")))

    console.print()
    console.print(_indented(Text(report.disclaimer, style="dim")))
    console.print()
