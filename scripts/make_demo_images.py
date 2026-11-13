"""Make the three README demo images in docs/demo/ from lookfirst's real output.

    uv run python scripts/make_demo_images.py            all three (the sandbox one needs Docker)
    uv run python scripts/make_demo_images.py --no-sandbox

1. hook.svg: the hook's answer when an agent runs `npm install` in a freshly cloned repo
   whose postinstall script steals the npm token (the credential_theft_javascript fixture).
2. sandbox.svg: `lookfirst check csvplot --sandbox` on that same repo, run in Docker.
3. lookalike.svg: the identity check on a made-up copy of Ollama (a test-suite pair,
   served from recordings, so it never calls GitHub).

The fake repo is built in a temporary folder and nothing from it runs on this computer:
the hook only reads it, and the sandbox runs it inside Docker. The temporary folder's
path is shown as ~/code in the hook image.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

import httpx
from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from conftest import FIXTURES  # noqa: E402  (tests/ holds the recordings and the pairs)
from test_identity import NOW, PAIRS, pair_handler  # noqa: E402

from lookfirst import hook  # noqa: E402
from lookfirst.identity.check import check_identity  # noqa: E402
from lookfirst.identity.github import GitHubData  # noqa: E402
from lookfirst.identity.popular_index import load_index  # noqa: E402
from lookfirst.pipeline import CHECKS, run_check  # noqa: E402
from lookfirst.targets.models import ResolvedTarget, TargetSpec  # noqa: E402
from lookfirst.verdict.render_terminal import make_console, render_terminal  # noqa: E402
from lookfirst.verdict.schema import CheckKind, NotChecked  # noqa: E402
from lookfirst.verdict.scoring import build_report  # noqa: E402

OUT = ROOT / "docs" / "demo"
WIDTH = 96
FIXTURE = FIXTURES / "install" / "credential_theft_javascript"
PACKAGE_JSON = {
    "name": "csvplot",
    "version": "0.3.1",
    "description": "Plot a CSV file in your terminal.",
    "bin": {"csvplot": "bin/csvplot.js"},
    "scripts": {"postinstall": "node scripts/setup.js"},
    "license": "MIT",
}
README = "# csvplot\n\nPlot a CSV file in your terminal.\n\n## Install\n\n```sh\nnpm install\n```\n"


def git(*args: str, cwd: Path) -> None:
    subprocess.run(  # noqa: S603
        ["git", "-c", "user.name=csvplot", "-c", "user.email=csvplot@example.com", *args],  # noqa: S607
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def build_csvplot(base: Path) -> Path:
    """A fake repo made from the fixture, cloned so the hook sees a fresh clone."""
    origin = base / "origin" / "csvplot"
    (origin / "scripts").mkdir(parents=True)
    (origin / "bin").mkdir()
    shutil.copy(FIXTURE / "scripts" / "setup.js", origin / "scripts" / "setup.js")
    (origin / "package.json").write_text(json.dumps(PACKAGE_JSON, indent=2) + "\n")
    (origin / "bin" / "csvplot.js").write_text(
        '#!/usr/bin/env node\nconsole.log("csvplot: not implemented in this demo copy.");\n'
    )
    (origin / "README.md").write_text(README)
    git("init", "-q", "-b", "main", cwd=origin)
    git("add", "-A", cwd=origin)
    git("commit", "-q", "-m", "csvplot 0.3.1", cwd=origin)
    code = base / "code"
    code.mkdir()
    git("clone", "-q", str(origin), "csvplot", cwd=code)
    return code / "csvplot"


def save(console: Console, name: str, title: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(console.export_svg(title=title))
    print(f"wrote {OUT / name}")


def hook_image(repo: Path) -> None:
    payload = {
        "session_id": "demo",
        "cwd": str(repo),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install", "description": "Install csvplot"},
    }
    stdin = io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()), encoding="utf-8")
    out = io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = stdin
    try:
        with redirect_stdout(out):
            hook.main([])
    finally:
        sys.stdin = old_stdin
    answer = json.loads(out.getvalue())
    reason = answer["hookSpecificOutput"]["permissionDecisionReason"]
    reason = reason.replace(str(repo.parent), "~/code")
    console = make_console(record=True, width=WIDTH, file=io.StringIO())
    console.print(Text("Claude Code wants to run, in a repo cloned an hour ago:", style="dim"))
    console.print(Text("  $ npm install", style="bold"))
    console.print()
    console.print(Text("lookfirst's hook answered: deny", style="bold red"))
    console.print(Text(reason))
    save(console, "hook.svg", "lookfirst hook")


def sandbox_image(repo: Path) -> None:
    report = run_check("csvplot", sandbox=True, cwd=repo.parent)
    console = make_console(record=True, width=WIDTH, file=io.StringIO())
    console.print(Text("$ lookfirst check csvplot --sandbox", style="bold"))
    render_terminal(report, console)
    save(console, "sandbox.svg", "lookfirst check --sandbox")


def lookalike_image() -> None:
    pair = json.loads((PAIRS / "copied_readme_new_account.json").read_text())
    handler, repo = pair_handler(pair)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = ResolvedTarget(
        TargetSpec(kind="github", raw=pair["target"]),
        root=None,
        resolved=f"{pair['target']}@{'4c1d0e9' + '0' * 33}",  # a made-up commit
        metadata={"repo": repo},
    )
    outcome = check_identity(target, GitHubData(client, has_token=True), load_index(), now=NOW)
    left_out = [
        NotChecked(check=kind, what=label, reason="left out of this example")
        for kind, label in CHECKS.items()
        if kind is not CheckKind.identity
    ]
    report = build_report(
        target=target.to_schema(),
        findings=outcome.findings,
        checked=[CheckKind.identity],
        not_checked=left_out,
        identity=outcome.result,
        now=datetime(2026, 11, 9, tzinfo=UTC),
    )
    console = make_console(record=True, width=WIDTH, file=io.StringIO())
    console.print(Text("A made-up copy of Ollama, from lookfirst's tests", style="dim"))
    console.print(Text(f"$ lookfirst check {pair['target']}", style="bold"))
    render_terminal(report, console)
    save(console, "lookalike.svg", "lookfirst check (identity)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-sandbox", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as base:
        repo = build_csvplot(Path(base))
        hook_image(repo)
        if not args.no_sandbox:
            sandbox_image(repo)
    lookalike_image()


if __name__ == "__main__":
    main()
