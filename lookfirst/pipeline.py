"""One check from start to finish: target, then checks, then the verdict."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from lookfirst.core.config import DEFAULT_LIMITS, Limits
from lookfirst.core.errors import CouldntCheckError
from lookfirst.static.checks import run_static_checks
from lookfirst.static.fetch import RemoteReader
from lookfirst.targets.base import open_target, parse_target
from lookfirst.verdict.schema import CheckKind, NotChecked, Report
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
NOT_FOR_COMMANDS = "doesn't apply to a shell command"


def run_check(
    raw: str,
    *,
    sandbox: bool = False,
    cwd: Path | None = None,
    limits: Limits = DEFAULT_LIMITS,
    now: datetime | None = None,
    reader: RemoteReader | None = None,
) -> Report:
    spec = parse_target(raw, cwd=cwd or Path.cwd())
    own_reader = reader is None
    reader = reader or RemoteReader()
    try:
        with open_target(spec, limits=limits) as target:
            result = run_static_checks(target, reader)
            if result.core_unreadable:
                raise CouldntCheckError(
                    "Couldn't check this command: the script it runs couldn't be read "
                    f"({result.core_unreadable[0]}).",
                    hint="lookfirst never gives a verdict on a script it hasn't read. "
                    "Check your connection and try again.",
                )
            not_checked: list[NotChecked] = []
            for kind, label in CHECKS.items():
                if kind in result.checked:
                    continue
                if kind is CheckKind.sandbox and not sandbox:
                    reason, how = "not requested", "add --sandbox"
                elif kind in (CheckKind.agent_config, CheckKind.injection) and target.root is None:
                    reason, how = NOT_FOR_COMMANDS, None
                else:
                    reason, how = NOT_BUILT, None
                not_checked.append(
                    NotChecked(check=kind, what=label, reason=reason, how_to_enable=how)
                )
            return build_report(
                target=target.to_schema(),
                findings=result.findings,
                checked=result.checked,
                not_checked=not_checked,
                now=now,
            )
    finally:
        if own_reader:
            reader.close()
