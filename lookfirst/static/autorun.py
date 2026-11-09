"""Commands that run when you open the folder: VS Code tasks, dev containers and direnv."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from lookfirst.static import jsonc
from lookfirst.static.files import read_text, walk
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.shell_rules import ShellAnalyzer

_DEVCONTAINER_KEYS = {
    "initializeCommand": "on your computer, when you open it in a dev container",
    "onCreateCommand": "inside the dev container, when it's created",
    "updateContentCommand": "inside the dev container, when it's created",
    "postCreateCommand": "inside the dev container, when it's created",
    "postStartCommand": "inside the dev container, every time it starts",
    "postAttachCommand": "inside the dev container, every time you connect",
}


def _line_of(text: str, needle: str) -> int:
    at = text.find(needle)
    return 1 if at < 0 else text.count("\n", 0, at) + 1


def _as_commands(value: Any) -> list[str]:
    """Dev container commands can be a string, a list of words, or named commands."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [shlex.join(value)]
    if isinstance(value, dict):
        return [c for v in value.values() for c in _as_commands(v)]
    return []


def _run(
    analyzer: ShellAnalyzer, out: Collector, command: str, path: str, line: int, runs: str
) -> None:
    out.add("install_path.autorun_on_open", path=path, line=line, excerpt=command, runs=runs)
    analyzer.analyze(Snippet(command, Origin(path=path, line=line, runs=runs)))


def _vscode_tasks(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    rel = ".vscode/tasks.json"
    text = read_text(root, rel)
    if text is None:
        return
    try:
        data = jsonc.loads(text)
    except ValueError:
        out.add("install_path.unparsed", path=rel)
        return
    tasks = data.get("tasks") if isinstance(data, dict) else None
    for task in tasks if isinstance(tasks, list) else []:
        if not isinstance(task, dict):
            continue
        options = task.get("runOptions") if isinstance(task.get("runOptions"), dict) else {}
        if options.get("runOn") != "folderOpen":
            continue
        command = task.get("command")
        if not isinstance(command, str):
            continue
        args = (
            [a for a in task.get("args", []) if isinstance(a, str)]
            if isinstance(task.get("args"), list)
            else []
        )
        full = command + (" " + shlex.join(args) if args else "")
        _run(
            analyzer,
            out,
            full,
            rel,
            _line_of(text, command),
            "when you open the folder in VS Code (it asks first)",
        )


def _devcontainers(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    candidates = [".devcontainer/devcontainer.json", ".devcontainer.json"]
    folder = root / ".devcontainer"
    if folder.is_dir() and not folder.is_symlink():
        candidates += [
            f".devcontainer/{p}"
            for p in walk(folder, max_files=50)
            if p.endswith("devcontainer.json")
        ]
    for rel in dict.fromkeys(candidates):
        text = read_text(root, rel)
        if text is None:
            continue
        try:
            data = jsonc.loads(text)
        except ValueError:
            out.add("install_path.unparsed", path=rel)
            continue
        if not isinstance(data, dict):
            continue
        for key, runs in _DEVCONTAINER_KEYS.items():
            for command in _as_commands(data.get(key)):
                _run(analyzer, out, command, rel, _line_of(text, f'"{key}"'), runs)


def _envrc(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    text = read_text(root, ".envrc")
    if text is None:
        return
    runs = "when you enter the folder with direnv (it asks first)"
    out.add("install_path.autorun_on_open", path=".envrc", line=1, runs=runs)
    analyzer.analyze(Snippet(text, Origin(path=".envrc", line=1, runs=runs)))


def check_autorun(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    _vscode_tasks(root, analyzer, out)
    _devcontainers(root, analyzer, out)
    _envrc(root, analyzer, out)
