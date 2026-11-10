"""One check from start to finish: target, then checks, then the verdict."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from lookfirst.core.config import DEFAULT_LIMITS, Limits, cache_dir
from lookfirst.core.errors import CouldntCheckError, FetchError
from lookfirst.core.http import github_token, make_client
from lookfirst.identity.check import IdentityOutcome, check_identity
from lookfirst.identity.github import GitHubData
from lookfirst.identity.popular_index import load_index
from lookfirst.scanners.check import run_package_check
from lookfirst.static.checks import run_static_checks
from lookfirst.static.fetch import RemoteReader
from lookfirst.targets.base import open_target, parse_target
from lookfirst.targets.models import ResolvedTarget
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
    # One-liners are compared with official sites offline, so they need no GitHub token.
    token = None if spec.kind == "oneliner" else github_token()
    try:
        with open_target(spec, limits=limits, token=token) as target:
            result = run_static_checks(target, reader)
            if result.core_unreadable:
                raise CouldntCheckError(
                    "Couldn't check this command: the script it runs couldn't be read "
                    f"({result.core_unreadable[0]}).",
                    hint="lookfirst never gives a verdict on a script it hasn't read. "
                    "Check your connection and try again.",
                )
            identity = _identity(target, token, now or datetime.now(UTC))
            package = run_package_check(target)
            checked = (
                ([CheckKind.identity] if identity.ran else [])
                + result.checked
                + ([CheckKind.package] if package.ran else [])
            )
            not_checked: list[NotChecked] = []
            for kind, label in CHECKS.items():
                if kind is CheckKind.identity:
                    for what, reason, how in identity.gaps:
                        shown = label if not identity.ran else what
                        not_checked.append(
                            NotChecked(check=kind, what=shown, reason=reason, how_to_enable=how)
                        )
                    if identity.ran or identity.gaps:
                        continue
                if kind is CheckKind.package and package.gaps:
                    not_checked += package.gaps
                    continue
                if kind in checked:
                    continue
                if kind is CheckKind.sandbox and not sandbox:
                    reason, how = "not requested", "add --sandbox"
                elif (
                    kind in (CheckKind.agent_config, CheckKind.injection, CheckKind.package)
                    and target.root is None
                ):
                    reason, how = NOT_FOR_COMMANDS, None
                else:
                    reason, how = NOT_BUILT, None
                not_checked.append(
                    NotChecked(check=kind, what=label, reason=reason, how_to_enable=how)
                )
            return build_report(
                target=target.to_schema(),
                findings=result.findings + identity.findings + package.findings,
                checked=checked,
                not_checked=not_checked,
                identity=identity.result,
                tools=package.tools,
                now=now,
            )
    finally:
        if own_reader:
            reader.close()


def _identity(target: ResolvedTarget, token: str | None, now: datetime) -> IdentityOutcome:
    """Run the identity check. A GitHub failure means "not checked", never a crash."""
    if target.spec.kind == "oneliner":
        return check_identity(target, None, load_index(), now=now)
    with make_client(token=token) as client:
        data = GitHubData(client, has_token=bool(token), cache=cache_dir())
        try:
            return check_identity(target, data, load_index(), now=now)
        except FetchError as exc:
            reason = f"couldn't reach GitHub: {exc.message.rstrip('.')}"
            return IdentityOutcome(
                ran=False, gaps=[("Is this the real project?", reason, exc.hint)]
            )
