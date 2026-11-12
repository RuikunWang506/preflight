"""The `lookfirst` command.

Exit codes: 0 Looks OK, 10 Caution, 20 Don't run, 1 error. Usage mistakes
exit 1 too, not the usual 2, because Claude Code reads exit 2 from a hook
as "block this command".
"""

import os
import sys
from collections.abc import Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.text import Text

from lookfirst import __version__
from lookfirst.core.errors import LookfirstError
from lookfirst.core.textsafe import visible
from lookfirst.pipeline import run_check
from lookfirst.sandbox.runner import DEFAULT_TIMEOUT, SandboxOptions
from lookfirst.verdict.render_markdown import render_markdown
from lookfirst.verdict.render_terminal import make_console, render_terminal

EXIT_ERROR = 1
_USAGE_ERROR = 2  # what typer uses for a usage mistake

app = typer.Typer(
    name="lookfirst",
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help=(
        "Check a GitHub repo, shell one-liner or package before you or your AI agent runs it. "
        "lookfirst lowers risk; it doesn't guarantee safety."
    ),
)


class Network(StrEnum):
    sinkhole = "sinkhole"
    passthrough = "passthrough"
    offline = "offline"


class Arch(StrEnum):
    arm64 = "arm64"
    amd64 = "amd64"


sandbox_app = typer.Typer(
    name="sandbox",
    no_args_is_help=True,
    help="The Docker sandbox that --sandbox runs installs in.",
)
app.add_typer(sandbox_app)


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"lookfirst {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Check a GitHub repo, shell one-liner or package before you or your AI agent runs it."""


def print_error(message: str, hint: str | None = None) -> None:
    console = make_console(stderr=True)
    console.print(Text.assemble(("lookfirst: ", "bold red"), visible(message)))
    if hint:
        console.print(Text(visible(hint, keep_newlines=True), style="dim"))


@app.command()
def check(
    target: Annotated[
        str,
        typer.Argument(
            help=(
                "What to check: a GitHub URL or owner/repo (optionally @branch, tag or commit), "
                'a folder, a quoted shell command such as "curl ... | bash", '
                "npm:<name> or pypi:<name>."
            ),
            show_default=False,
        ),
    ],
    sandbox: Annotated[
        bool,
        typer.Option(
            "--sandbox",
            help="Also run the install in a throwaway Docker sandbox and watch what it does.",
        ),
    ] = False,
    cmd: Annotated[
        str | None,
        typer.Option(
            "--cmd",
            metavar="COMMAND",
            help="With --sandbox: the install command to run, instead of lookfirst's guess.",
        ),
    ] = None,
    network: Annotated[
        Network,
        typer.Option(
            "--network",
            case_sensitive=False,
            help=(
                "With --sandbox: sinkhole (the default) records every request and lets only "
                "package registries and the project's own sites through; passthrough lets "
                "everything through; offline has no network at all."
            ),
        ),
    ] = Network.sinkhole,
    arch: Annotated[
        Arch | None,
        typer.Option(
            "--arch",
            case_sensitive=False,
            help=(
                "With --sandbox: arm64 or amd64. The default is this computer's own; amd64 on "
                "Apple Silicon runs under emulation."
            ),
        ),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option(
            "--timeout",
            min=10,
            max=1800,
            metavar="SECONDS",
            help="With --sandbox: stop the dry run after this many seconds.",
        ),
    ] = DEFAULT_TIMEOUT,
    json_output: Annotated[bool, typer.Option("--json", help="Print the report as JSON.")] = False,
    report_file: Annotated[
        Path | None,
        typer.Option(
            "--report",
            metavar="FILE",
            help="Also save the report as Markdown to FILE.",
            dir_okay=False,
        ),
    ] = None,
) -> None:
    """Check a target before you run it. Nothing from the target is ever run on this computer."""
    status = make_console(stderr=True)
    options = SandboxOptions(
        command=cmd, network=network.value, arch=arch.value if arch else None, timeout=timeout
    )
    if sandbox:
        minutes = f"{timeout // 60} minutes" if timeout >= 120 else f"{timeout} seconds"
        status.print(Text(f"Running the install in the sandbox (up to {minutes})...", style="dim"))
    try:
        report = run_check(
            target,
            sandbox=sandbox,
            sandbox_options=options,
            on_sandbox_build=lambda: status.print(
                Text("Building the sandbox image (first time only, about a minute)...", style="dim")
            ),
        )
    except LookfirstError as exc:
        print_error(exc.message, exc.hint)
        raise typer.Exit(EXIT_ERROR) from None

    if report_file is not None:
        try:
            report_file.write_text(render_markdown(report), encoding="utf-8")
        except OSError as exc:
            print_error(f"Couldn't save the report to {report_file}: {exc.strerror or exc}.")
            raise typer.Exit(EXIT_ERROR) from None

    if json_output:
        sys.stdout.write(report.model_dump_json(indent=2) + "\n")
    else:
        render_terminal(report, make_console())
    raise typer.Exit(report.exit_code)


@app.command("update-index")
def update_index() -> None:
    """Refresh lookfirst's list of popular repos from GitHub. Needs a GitHub token."""
    from lookfirst.core.http import github_token, make_client
    from lookfirst.identity import popular_index

    token = github_token()
    if not token:
        print_error(
            "Updating the list of popular repos needs a GitHub token.",
            "Set GITHUB_TOKEN, or sign in with `gh auth login`, then try again.",
        )
        raise typer.Exit(EXIT_ERROR)
    console = make_console(stderr=True)
    console.print(
        "Searching GitHub for the most-starred and fastest-rising repos (about 3 minutes)..."
    )
    try:
        with make_client(token=token) as client:
            data = popular_index.build(client)
    except LookfirstError as exc:
        print_error(exc.message, exc.hint)
        raise typer.Exit(EXIT_ERROR) from None
    path = popular_index.save_to_cache(data)
    console.print(f"Saved {len(popular_index.load_index()):,} popular repos to {path}.")


@app.command("mcp")
def mcp() -> None:
    """Run lookfirst as an MCP server over stdio, so a coding agent can call it."""
    from lookfirst.mcp_server import main as mcp_main

    mcp_main()


@app.command("hook", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def hook() -> None:
    """Claude Code's PreToolUse hook for the Bash tool. Reads the hook's JSON on stdin."""
    # `lookfirst hook` normally never gets here: lookfirst/entry.py hands it off before
    # Typer loads, to keep it fast. This is for --help and for running cli.py directly.
    from lookfirst.hook import main as hook_main

    raise typer.Exit(hook_main(()))


@sandbox_app.command("build")
def sandbox_build(
    arch: Annotated[
        Arch | None,
        typer.Option(
            "--arch", case_sensitive=False, help="arm64 or amd64 (default: this computer's)."
        ),
    ] = None,
) -> None:
    """Build the sandbox image and fetch the recording proxy, so --sandbox starts quickly."""
    from lookfirst.sandbox import image
    from lookfirst.sandbox.docker import DockerError, find_docker

    docker = find_docker()
    engine = docker.engine() if docker else None
    if docker is None or engine is None:
        print_error(
            "Docker isn't installed or isn't running.",
            "Install OrbStack or Docker Desktop and start it, then try again.",
        )
        raise typer.Exit(EXIT_ERROR)
    chosen = arch.value if arch else engine[1]
    console = make_console(stderr=True)
    console.print(Text(f"Building the {chosen} sandbox image (about a minute)...", style="dim"))
    try:
        built = image.ensure_sandbox_image(docker, chosen)
        image.ensure_proxy_image(docker)
    except DockerError as exc:
        print_error(f"The sandbox image couldn't be built: {exc}")
        raise typer.Exit(EXIT_ERROR) from None
    console.print(f"Ready: {image.sandbox_tag(chosen)} ({built[:19]}), and the recording proxy.")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its exit code."""
    command = typer.main.get_command(app)
    try:
        command.main(
            args=list(argv) if argv is not None else None,
            prog_name="lookfirst",
            standalone_mode=True,
        )
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return EXIT_ERROR if code == _USAGE_ERROR else code
        return EXIT_ERROR
    except Exception as exc:
        if os.environ.get("LOOKFIRST_DEBUG"):
            raise
        print_error(
            f"Something went wrong inside lookfirst ({type(exc).__name__}). This is a bug.",
            "Run again with LOOKFIRST_DEBUG=1 to see the details.",
        )
        return EXIT_ERROR
    return 0
