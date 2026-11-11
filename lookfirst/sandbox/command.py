"""What the sandbox runs (SPEC section 8, M5 decision 6): `--cmd` if given, otherwise
lookfirst's best guess at what a person installing the target would run."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from lookfirst.static.files import exists, read_text
from lookfirst.static.readme import install_blocks
from lookfirst.targets.models import ResolvedTarget

APP = "/tmp/lookfirst-app"  # an empty project for installing a package into
MAX_COMMAND = 4000
_READMES = ("README.md", "readme.md", "Readme.md", "README.markdown", "README.rst", "README")
_INSTALL = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b|\bpip3?\s+install\b|\bpipx\s+install\b"
    r"|\buv\s+(?:pip\s+install|sync|tool\s+install)\b|\bpoetry\s+install\b"
    r"|\bmake(?:\s+install)?\s*$|\b(?:ba|z)?sh\s+\S*install\S*|\./install\S*"
    r"|\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bcargo\s+install\b"
    r"|\bgo\s+install\b|\bpython3?\s+setup\.py\s+install\b",
    re.MULTILINE,
)
_CLONE = re.compile(r"^\s*git\s+clone\b")
_CD = re.compile(r"^\s*cd\s+\S+\s*$")


@dataclass(frozen=True)
class Chosen:
    command: str  # shell text, run with bash
    why: str  # plain English
    folder: str = "/work"  # where it runs


def _readme_command(target: ResolvedTarget) -> Chosen | None:
    root = target.root
    if root is None:
        return None
    for name in _READMES:
        text = read_text(root, name)
        if text is None:
            continue
        for block in install_blocks(text):
            if not _INSTALL.search(block.text):
                continue
            lines, skip_cd = [], False
            for line in block.text.splitlines():
                if _CLONE.match(line):  # the project is already in the sandbox
                    skip_cd = True
                    continue
                if skip_cd and _CD.match(line):
                    skip_cd = False
                    continue
                if line.strip():
                    lines.append(re.sub(r"^(\s*)sudo\s+", r"\1", line))  # there's no sudo here
            command = "\n".join(lines).strip()
            if command and len(command) <= MAX_COMMAND:
                return Chosen(command, f"the install instructions in {name} (line {block.line})")
        return None
    return None


def choose_command(target: ResolvedTarget, override: str | None = None) -> Chosen | None:
    if override:
        return Chosen(override[:MAX_COMMAND], "the command you gave with --cmd")
    kind = target.spec.kind
    if kind in ("oneliner", "mcp_command") and target.spec.command:
        return Chosen(target.spec.command, "the command itself", APP)
    meta = target.metadata
    if kind == "npm" and isinstance(meta.get("npm"), dict):
        name, version = meta["npm"].get("name"), meta["npm"].get("version")
        if isinstance(name, str) and isinstance(version, str):
            spec = shlex.quote(f"{name}@{version}")
            return Chosen(f"npm install {spec}", "installing the package with npm", APP)
    if kind == "pypi" and isinstance(meta.get("pypi"), dict):
        info = meta["pypi"].get("info") or {}
        name, version = info.get("name"), info.get("version")
        if isinstance(name, str) and isinstance(version, str):
            spec = shlex.quote(f"{name}=={version}")
            return Chosen(f"pip install {spec}", "installing the package with pip", APP)
    root = target.root
    if root is None:
        return None
    readme = _readme_command(target)
    if readme is not None:
        return readme
    if exists(root, "package.json"):
        return Chosen("npm install", "npm install, since it has a package.json")
    if exists(root, "pyproject.toml") or exists(root, "setup.py"):
        return Chosen("pip install .", "pip install ., since it's a Python project")
    makefile = read_text(root, "Makefile")
    if makefile and re.search(r"^install\s*:", makefile, re.MULTILINE):
        return Chosen("make install", "make install, from its Makefile")
    if exists(root, "install.sh"):
        return Chosen("bash install.sh", "its install.sh")
    return None
