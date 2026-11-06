"""The `lookfirst` command.

Exit codes: 0 Looks OK, 10 Caution, 20 Don't run, 1 error. Usage mistakes
exit 1 too, not the usual 2, because Claude Code reads exit 2 from a hook
as "block this command".
"""

import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer
from rich.text import Text

from lookfirst import __version__
from lookfirst.core.errors import LookfirstError
from lookfirst.core.textsafe import visible
from lookfirst.pipeline import run_check
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
            "--sandbox", help="Also run the install in a throwaway sandbox (coming in M5)."
        ),
    ] = False,
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
    try:
        report = run_check(target, sandbox=sandbox)
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
