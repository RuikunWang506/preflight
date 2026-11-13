"""The README and the launch docs stay true to lookfirst: required sections, working links,
real commands and options, the right exit codes, and demo images with nobody's home folder.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer

from lookfirst.cli import app
from lookfirst.verdict.schema import EXIT_CODES

ROOT = Path(__file__).parent.parent
README = ROOT / "README.md"
DOCS = [
    README,
    ROOT / "docs" / "THREAT_MODEL.md",
    ROOT / "docs" / "RELEASE-NOTES-0.1.0.md",
    ROOT / "docs" / "demo" / "README.md",
    ROOT / "plugin" / "README.md",
]
SAFETY = "lookfirst lowers risk; it doesn't guarantee safety."
LINK = re.compile(r"\]\(([^)\s]+)\)")


def code_blocks(text: str) -> list[str]:
    return re.findall(r"```[a-z]*\n(.*?)```", text, flags=re.DOTALL)


@pytest.mark.parametrize(
    "heading",
    [
        "## The 30-second demo",
        "## Install",
        "### The Claude Code plugin",
        "## What lookfirst checks",
        "## What it doesn't check",
        "## Threat model in brief",
        "## What leaves your computer",
        "## Official sources",
    ],
)
def test_the_readme_has_every_section_spec_section_12_asks_for(heading: str) -> None:
    assert heading in README.read_text().splitlines()


@pytest.mark.parametrize(
    "doc",
    [d for d in DOCS if d.parent.name != "demo"],  # the demo notes only say how images were made
    ids=lambda p: str(p.relative_to(ROOT)),
)
def test_every_doc_says_lookfirst_lowers_risk_without_guarantees(doc: Path) -> None:
    assert SAFETY in doc.read_text()


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_local_link_points_at_a_file_that_exists(doc: Path) -> None:
    for link in LINK.findall(doc.read_text()):
        if link.startswith(("http://", "https://", "#")):
            continue
        path = (doc.parent / link.split("#")[0]).resolve()
        assert path.exists(), f"{doc.name} links to {link}, which doesn't exist"


def _commands() -> dict[str, set[str]]:
    """Each lookfirst command and its options, read from the real command line."""
    group = typer.main.get_command(app)
    found = {}
    for name, command in group.commands.items():  # type: ignore[attr-defined]
        found[name] = {opt for p in command.params for opt in p.opts if opt.startswith("-")}
    return found


def test_every_command_and_option_in_the_readme_exists() -> None:
    commands = _commands()
    used = 0
    for block in code_blocks(README.read_text()):
        for line in block.splitlines():
            words = line.split("#")[0].split()
            if words[:2] == ["uv", "run"]:
                words = words[2:]
            if not words or words[0] != "lookfirst":
                continue
            used += 1
            assert words[1] in commands, f"README uses `lookfirst {words[1]}`, which doesn't exist"
            for word in words[2:]:
                if word.startswith("--"):
                    assert word in commands[words[1]], f"`lookfirst {words[1]}` has no {word}"
    assert used >= 8


def test_the_readme_gives_the_real_exit_codes() -> None:
    text = README.read_text()
    labels = {"looks_ok": "Looks OK", "caution": "Caution", "dont_run": "Don't run"}
    for verdict, code in EXIT_CODES.items():
        assert f"**{code}** {labels[verdict]}" in text


def test_the_plugin_install_steps_match_the_marketplace_and_plugin_names() -> None:
    for doc in (README, ROOT / "plugin" / "README.md"):
        text = doc.read_text()
        assert "/plugin install lookfirst@lookfirst" in text
        assert "marketplace add lookfirst-dev/lookfirst" in text


@pytest.mark.parametrize("image", ["hook.svg", "sandbox.svg", "lookalike.svg"])
def test_demo_images_exist_and_show_no_home_folder(image: str) -> None:
    text = (ROOT / "docs" / "demo" / image).read_text()
    assert text.startswith("<svg")
    for private in ("/Users/", "/private/", "ruikunwang"):
        assert private not in text, f"{image} shows {private}"
    assert image in README.read_text()
