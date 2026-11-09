"""Run the three static checks on a fetched target: install paths, agent settings and
hidden prompts. Nothing from the target is run."""

from __future__ import annotations

from dataclasses import dataclass, field

from lookfirst.static.agent_configs import check_agent_configs
from lookfirst.static.autorun import check_autorun
from lookfirst.static.context import build_context
from lookfirst.static.fetch import RemoteReader
from lookfirst.static.injection import check_injection
from lookfirst.static.install_paths import check_install_paths
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.shell_rules import ShellAnalyzer
from lookfirst.targets.models import ResolvedTarget
from lookfirst.verdict.schema import CheckKind, Finding


@dataclass
class StaticResult:
    findings: list[Finding]
    checked: list[CheckKind] = field(default_factory=list)
    core_unreadable: list[str] = field(
        default_factory=list
    )  # why the main command couldn't be read


def run_static_checks(target: ResolvedTarget, reader: RemoteReader | None) -> StaticResult:
    ctx = build_context(target)
    out = Collector()
    analyzer = ShellAnalyzer(ctx, out, reader)
    checked: list[CheckKind] = []
    if target.root is not None:
        check_install_paths(
            target.root, target.manifest, analyzer, out, local=target.spec.kind == "local"
        )
        check_autorun(target.root, analyzer, out)
        checked.append(CheckKind.install_path)
        instruction_files = check_agent_configs(target.root, analyzer, out)
        checked.append(CheckKind.agent_config)
        check_injection(target.root, instruction_files, out)
        checked.append(CheckKind.injection)
    command = target.spec.command
    if command:
        analyzer.analyze(
            Snippet(command, Origin("command", 1, "when you run this command"), root_command=True)
        )
        if CheckKind.install_path not in checked:
            checked.append(CheckKind.install_path)
    return StaticResult(out.findings(), checked, analyzer.core_unreadable)
