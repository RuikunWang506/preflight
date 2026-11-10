"""The verdict rule (SPEC section 9). Pure functions, no I/O."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from lookfirst import __version__
from lookfirst.verdict.schema import (
    EXIT_CODES,
    SEVERITY_RANK,
    CheckKind,
    Finding,
    IdentityResult,
    NotChecked,
    Report,
    SandboxRun,
    Severity,
    Target,
    ToolRun,
    VerdictLabel,
)


def verdict_for(findings: Iterable[Finding]) -> VerdictLabel:
    """Any critical finding: Don't run. Otherwise any high: Caution. Otherwise: Looks OK."""
    severities = {f.severity for f in findings}
    if Severity.critical in severities:
        return VerdictLabel.dont_run
    if Severity.high in severities:
        return VerdictLabel.caution
    return VerdictLabel.looks_ok


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first; ties keep a stable order by check, then id."""
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.check.value, f.id))


def top_reasons(findings: Iterable[Finding], limit: int = 3) -> list[str]:
    """Titles of the most severe critical or high findings: the reasons behind the verdict."""
    serious = [
        f for f in sort_findings(findings) if f.severity in (Severity.critical, Severity.high)
    ]
    return [f.title for f in serious[:limit]]


def build_report(
    *,
    target: Target,
    findings: Iterable[Finding],
    checked: Iterable[CheckKind],
    not_checked: Iterable[NotChecked],
    identity: IdentityResult | None = None,
    sandbox: SandboxRun | None = None,
    tools: Iterable[ToolRun] = (),
    now: datetime | None = None,
    tool_version: str = __version__,
) -> Report:
    ordered = sort_findings(findings)
    verdict = verdict_for(ordered)
    return Report(
        tool_version=tool_version,
        generated_at=now or datetime.now(UTC),
        target=target,
        verdict=verdict,
        exit_code=EXIT_CODES[verdict],
        summary=top_reasons(ordered),
        findings=ordered,
        identity=identity,
        sandbox=sandbox,
        checked=list(checked),
        not_checked=list(not_checked),
        tools=list(tools),
    )
