"""One check from start to finish: target, then checks, then the verdict."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from lookfirst.core.config import DEFAULT_LIMITS, Limits
from lookfirst.targets.base import open_target, parse_target
from lookfirst.verdict.schema import CheckKind, Finding, NotChecked, Report
from lookfirst.verdict.scoring import build_report

# Every check, in the order the report lists them, with its plain-English name.
CHECKS: dict[CheckKind, str] = {
    CheckKind.identity: "Is this the real project?",
    CheckKind.install_path: "What installing it would run",
    CheckKind.agent_config: "Agent settings shipped with it",
    CheckKind.injection: "Hidden instructions aimed at AI agents",
    CheckKind.package: "Known-vulnerable or malicious packages",
    CheckKind.sandbox: "Sandbox dry run",
}

NOT_BUILT = "not built yet"


def run_check(
    raw: str,
    *,
    sandbox: bool = False,
    cwd: Path | None = None,
    limits: Limits = DEFAULT_LIMITS,
    now: datetime | None = None,
) -> Report:
    spec = parse_target(raw, cwd=cwd or Path.cwd())
    with open_target(spec, limits=limits) as target:
        findings: list[Finding] = []
        checked: list[CheckKind] = []
        not_checked: list[NotChecked] = []
        for kind, label in CHECKS.items():
            if kind is CheckKind.sandbox and not sandbox:
                not_checked.append(
                    NotChecked(
                        check=kind,
                        what=label,
                        reason="not requested",
                        how_to_enable="add --sandbox",
                    )
                )
            else:
                not_checked.append(NotChecked(check=kind, what=label, reason=NOT_BUILT))
        return build_report(
            target=target.to_schema(),
            findings=findings,
            checked=checked,
            not_checked=not_checked,
            now=now,
        )
