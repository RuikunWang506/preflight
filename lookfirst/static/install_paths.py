"""Find everything that would run when someone installs the target or follows its README
(SPEC section 5), and send it through the rules. Nothing is run."""

from __future__ import annotations

import json
import os
import re
import shlex
import tomllib
from pathlib import Path

from lookfirst.core.archive import ArchiveManifest
from lookfirst.static.code_rules import analyze_javascript, analyze_python
from lookfirst.static.files import exists, read_text
from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.readme import install_blocks
from lookfirst.static.shell_rules import ShellAnalyzer

_README_NAMES = ("README.md", "readme.md", "Readme.md", "README.markdown", "README")
_SCRIPT_DIRS = ("", "scripts/", "script/", "bin/", "tools/")
_SCRIPT_NAMES = ("install.sh", "setup.sh", "bootstrap.sh", "get.sh")
_NPM_HOOKS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "preprepare",
    "postprepare",
    "prepublish",
)
_PYPI_HOSTS = ("pypi.org", "files.pythonhosted.org", "pypi.python.org")
_MAKE_TARGET = re.compile(r"^([^\s:#=][^:=]*?)\s*::?(?!=)(.*)$")
_MAKE_VAR = re.compile(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]")
_JUST_RECIPE = re.compile(r"^@?([A-Za-z0-9_-]+)(?:\s+[^:=]*)?:(?!=)(.*)$")
_NODE_FILE = re.compile(r"\bnode\s+(?:--?[\w-]+(?:=\S+)?\s+)*([\w./-]+\.(?:c|m)?js)\b")
_PY_FILE = re.compile(r"\bpython3?\s+(?:-[\w-]+\s+)*([\w./-]+\.py)\b")


def _snippet(text: str, path: str, line: int, runs: str) -> Snippet:
    return Snippet(text, Origin(path=path, line=line, runs=runs))


def _readme(root: Path, analyzer: ShellAnalyzer) -> None:
    for name in _README_NAMES:
        text = read_text(root, name)
        if text is None:
            continue
        for block in install_blocks(text):
            runs = "if you follow the README's install steps"
            # README code is written for people and often has placeholders like <version>,
            # so lines that don't parse aren't reported for it.
            analyzer.analyze(
                Snippet(
                    block.text, Origin(path=name, line=block.line, runs=runs), report_unparsed=False
                )
            )
        return


def _scripts(root: Path, analyzer: ShellAnalyzer) -> None:
    for folder in _SCRIPT_DIRS:
        for name in _SCRIPT_NAMES:
            rel = folder + name
            text = read_text(root, rel)
            if text is not None:
                analyzer.analyze(_snippet(text, rel, 1, f"if you run {rel}"))


def make_recipes(text: str) -> tuple[dict[str, list[tuple[int, str]]], str | None]:
    """The recipes in a Makefile (target -> (line, command) pairs) and the default target."""
    recipes: dict[str, list[tuple[int, str]]] = {}
    default: str | None = None
    current: list[str] = []
    pending: tuple[int, str] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.startswith("\t") and current:
            body = raw[1:]
            if pending is not None:
                start, so_far = pending
                body = so_far + "\n" + body
            else:
                start = number
            if body.endswith("\\"):
                pending = (start, body)
                continue
            pending = None
            command = _MAKE_VAR.sub(r"${\1}", body.lstrip().lstrip("@-+").replace("$$", "$"))
            for target in current:
                recipes[target].append((start, command))
            continue
        pending = None
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _MAKE_TARGET.match(raw)
        if m and not raw.startswith((" ", "\t")):
            targets = m.group(1).split()
            current = targets
            for target in targets:
                recipes.setdefault(target, [])
                if (
                    default is None
                    and not target.startswith(".")
                    and "%" not in target
                    and "$" not in target
                ):
                    default = target
            inline = m.group(2).partition(";")[2].strip()
            if inline:
                for target in targets:
                    recipes[target].append((number, inline))
        else:
            current = []
    return recipes, default


def _makefile(root: Path, analyzer: ShellAnalyzer) -> None:
    for name in ("Makefile", "makefile", "GNUmakefile"):
        text = read_text(root, name)
        if text is None:
            continue
        recipes, default = make_recipes(text)
        chosen = [t for t in dict.fromkeys([default, "install", "setup"]) if t and t in recipes]
        for target in chosen:
            runs = "when you run make" if target == default else f"when you run make {target}"
            for line, command in recipes[target]:
                analyzer.analyze(_snippet(command, name, line, runs))
        return


def _justfile(root: Path, analyzer: ShellAnalyzer) -> None:
    for name in ("justfile", "Justfile", ".justfile"):
        text = read_text(root, name)
        if text is None:
            continue
        recipes: dict[str, list[tuple[int, str]]] = {}
        order: list[str] = []
        current: str | None = None
        for number, raw in enumerate(text.splitlines(), start=1):
            if raw[:1] in (" ", "\t") and current:
                body = re.sub(
                    r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}", r"${\1}", raw.strip().lstrip("@-")
                )
                if body and not body.startswith("#!"):
                    recipes[current].append((number, body))
                continue
            m = _JUST_RECIPE.match(raw)
            if m and not raw.lstrip().startswith(("#", "set ", "export ", "alias ")):
                current = m.group(1)
                recipes.setdefault(current, [])
                order.append(current)
            elif raw.strip():
                current = None
        default = "default" if "default" in recipes else (order[0] if order else None)
        for target in [
            t for t in dict.fromkeys([default, "install", "setup"]) if t and t in recipes
        ]:
            runs = "when you run just" if target == default else f"when you run just {target}"
            for line, command in recipes[target]:
                analyzer.analyze(_snippet(command, name, line, runs))
        return


def _dockerfile(root: Path, analyzer: ShellAnalyzer) -> None:
    text = read_text(root, "Dockerfile")
    if text is None:
        return
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        line = lines[i]
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line.rstrip()[:-1] + "\n" + lines[i]
        i += 1
        m = re.match(r"^\s*RUN\s+(.*)$", line, re.IGNORECASE | re.DOTALL)
        if not m:
            continue
        body = m.group(1).strip()
        heredoc = re.match(r"^<<-?['\"]?(\w+)['\"]?\s*$", body)
        if heredoc:
            end = heredoc.group(1)
            collected = []
            while i < len(lines) and lines[i].strip() != end:
                collected.append(lines[i])
                i += 1
            i += 1
            body = "\n".join(collected)
            start += 1
        elif body.startswith("["):
            try:
                args = json.loads(body)
            except ValueError:
                args = None
            if isinstance(args, list) and all(isinstance(a, str) for a in args):
                body = args[2] if len(args) >= 3 and args[1] in ("-c", "-lc") else shlex.join(args)
        while body.startswith("--"):  # RUN --mount=... flags
            body = body.split(None, 1)[1] if " " in body else ""
        if body:
            analyzer.analyze(_snippet(body, "Dockerfile", start, "when you build the Docker image"))


def _package_json(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    text = read_text(root, "package.json")
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        out.add("install_path.unparsed", path="package.json", runs="when you run npm install")
        return
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    hooks = [h for h in _NPM_HOOKS if isinstance(scripts.get(h), str)]
    for hook in hooks:
        command = scripts[hook]
        runs = (
            "when you run npm install in this folder"
            if "prepare" in hook
            else "when you run npm install"
        )
        line = _line_of(text, f'"{hook}"')
        out.add(
            "install_path.install_hook",
            path="package.json",
            line=line,
            excerpt=f"{hook}: {command}",
            runs=runs,
        )
        analyzer.analyze(_snippet(command, "package.json", line or 1, runs))
        for m in _NODE_FILE.finditer(command):
            _code_file(root, m.group(1), "javascript", runs, analyzer, out)
        for m in _PY_FILE.finditer(command):
            _code_file(root, m.group(1), "python", runs, analyzer, out)
    if not hooks and exists(root, "binding.gyp"):
        out.add(
            "install_path.install_hook",
            path="binding.gyp",
            runs="when you run npm install",
            data={"what": "builds native code with node-gyp"},
        )
    bins = data.get("bin")
    names = (
        list(bins)
        if isinstance(bins, dict)
        else ([data.get("name")] if isinstance(bins, str) else [])
    )
    if names:
        out.add(
            "install_path.adds_commands",
            path="package.json",
            line=_line_of(text, '"bin"'),
            data={"what": ", ".join(str(n) for n in names[:10])},
        )
    for section in ("dependencies", "optionalDependencies", "devDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for dep, spec in deps.items():
            if isinstance(spec, str) and re.match(
                r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?://|[\w-]+/[\w.-]+(?:#|$))", spec
            ):
                out.add(
                    "install_path.custom_package_index",
                    path="package.json",
                    line=_line_of(text, f'"{dep}"'),
                    excerpt=f"{dep}: {spec}",
                    runs="when you run npm install",
                )
                if spec.startswith("http://"):
                    out.add(
                        "install_path.plain_http",
                        path="package.json",
                        line=_line_of(text, f'"{dep}"'),
                        excerpt=f"{dep}: {spec}",
                    )


def _line_of(text: str, needle: str) -> int | None:
    at = text.find(needle)
    return None if at < 0 else text.count("\n", 0, at) + 1


def _code_file(
    root: Path, rel: str, language: str, runs: str, analyzer: ShellAnalyzer, out: Collector
) -> None:
    rel = os.path.normpath(rel)
    if rel.startswith("..") or os.path.isabs(rel):
        return  # only files inside the target
    text = read_text(root, rel)
    if text is None:
        return
    origin = Origin(path=rel, line=1, runs=runs)
    if language == "javascript":
        result = analyze_javascript(text, origin, out)
    else:
        result = analyze_python(text, origin, out, is_setup_py=False)
    for snippet in result.shell:
        analyzer.analyze(snippet)


def _setup_py(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    text = read_text(root, "setup.py")
    if text is None:
        return
    runs = "when you install it with pip"
    result = analyze_python(text, Origin(path="setup.py", line=1, runs=runs), out, is_setup_py=True)
    if result.install_hook:
        out.add(
            "install_path.install_hook",
            path="setup.py",
            line=_line_of(text, "cmdclass"),
            runs=runs,
            data={"what": "custom setup.py commands"},
        )
    for snippet in result.shell:
        analyzer.analyze(snippet)


def _pyproject(root: Path, analyzer: ShellAnalyzer, out: Collector) -> None:
    text = read_text(root, "pyproject.toml")
    if text is None:
        return
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        out.add("install_path.unparsed", path="pyproject.toml", runs="when you install it with pip")
        return
    runs = "when you install it with pip"
    build = data.get("build-system") or {}
    if build.get("backend-path"):
        out.add(
            "install_path.install_hook",
            path="pyproject.toml",
            line=_line_of(text, "backend-path"),
            runs=runs,
            data={"what": "builds with its own code"},
        )
    hatch = ((data.get("tool") or {}).get("hatch") or {}).get("build") or {}
    hook_tables = [hatch.get("hooks") or {}] + [
        (target or {}).get("hooks") or {}
        for target in (hatch.get("targets") or {}).values()
        if isinstance(target, dict)
    ]
    for hooks in hook_tables:
        custom = hooks.get("custom") if isinstance(hooks, dict) else None
        if isinstance(custom, dict):
            path = str(custom.get("path") or "hatch_build.py")
            out.add(
                "install_path.install_hook",
                path="pyproject.toml",
                line=_line_of(text, "hooks.custom"),
                runs=runs,
                data={"what": f"a custom build hook ({path[:80]})"},
            )
            _code_file(root, path, "python", runs, analyzer, out)
    if ((data.get("tool") or {}).get("setuptools") or {}).get("cmdclass"):
        out.add(
            "install_path.install_hook",
            path="pyproject.toml",
            line=_line_of(text, "cmdclass"),
            runs=runs,
            data={"what": "custom setuptools commands"},
        )


def _requirements(root: Path, out: Collector) -> None:
    files = [p.relative_to(root).as_posix() for p in sorted(root.glob("requirements*.txt"))]
    files += [p.relative_to(root).as_posix() for p in sorted(root.glob("requirements/*.txt"))]
    seen: set[str] = set()
    while files:
        rel = files.pop(0)
        if rel in seen or len(seen) > 20:
            continue
        seen.add(rel)
        text = read_text(root, rel)
        if text is None:
            continue
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.split(" #", 1)[0].strip()
            if not line or line.startswith("#"):
                continue
            where = {
                "path": rel,
                "line": number,
                "excerpt": line,
                "runs": "when you run pip install -r " + rel,
            }
            parts = line.split()
            if parts[0] in ("-r", "--requirement", "-c", "--constraint") and len(parts) > 1:
                files.append(os.path.normpath(os.path.join(os.path.dirname(rel), parts[1])))
                continue
            index = None
            for flag in ("-i", "--index-url", "--extra-index-url", "-f", "--find-links"):
                if parts[0] == flag and len(parts) > 1:
                    index = parts[1]
                elif parts[0].startswith(flag + "="):
                    index = parts[0].split("=", 1)[1]
            if index is not None:
                if not any(h in index for h in _PYPI_HOSTS):
                    out.add("install_path.custom_package_index", **where)
                if index.startswith("http://"):
                    out.add("install_path.plain_http", **where)
                continue
            if parts[0] == "--trusted-host":
                out.add("install_path.custom_package_index", **where)
                continue
            if re.search(r"(?:git|hg|svn|bzr)\+|@\s*https?://|^https?://|^-e\s+\S*https?://", line):
                out.add("install_path.custom_package_index", **where)
                if "http://" in line:
                    out.add("install_path.plain_http", **where)


def _manifest(manifest: ArchiveManifest | None, out: Collector) -> None:
    if manifest is None:
        return
    prefix = manifest.root + "/" if manifest.root else ""

    def shown(path: str) -> str:
        return path.removeprefix(prefix)

    for entry in manifest.skipped:
        if "outside" in entry.reason:
            out.add(
                "install_path.escaping_archive_path",
                path=shown(entry.path),
                data={"what": entry.reason},
            )
        elif "letter case" in entry.reason:
            out.add(
                "install_path.case_collision", path=shown(entry.path), data={"what": entry.reason}
            )
    for link in manifest.links:
        if link.kind == "symlink":
            resolved = os.path.normpath(os.path.join(os.path.dirname(link.path), link.target))
        else:  # hard link targets are named from the top of the archive
            resolved = os.path.normpath(link.target)
        outside = link.target.startswith("/") or resolved.startswith("..")
        if not outside and prefix and not (resolved + "/").startswith(prefix):
            outside = True  # it leaves the project's folder inside the archive
        if outside:
            out.add(
                "install_path.outside_link",
                path=shown(link.path),
                data={"what": f"points to {link.target[:150]}"},
            )


def _local_links(root: Path, out: Collector, limit: int = 20_000) -> None:
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            count += 1
            if count > limit:
                return
            path = Path(dirpath) / name
            if path.is_symlink():
                try:
                    target = os.readlink(path)
                except OSError:
                    continue
                resolved = (path.parent / target).resolve()
                if not resolved.is_relative_to(root.resolve()):
                    out.add(
                        "install_path.outside_link",
                        path=path.relative_to(root).as_posix(),
                        data={"what": f"points to {target[:150]}"},
                    )
        dirnames[:] = [
            d
            for d in dirnames
            if d not in (".git", "node_modules") and not (Path(dirpath) / d).is_symlink()
        ]


def check_install_paths(
    root: Path,
    manifest: ArchiveManifest | None,
    analyzer: ShellAnalyzer,
    out: Collector,
    *,
    local: bool,
) -> None:
    _manifest(manifest, out)
    if local:
        _local_links(root, out)
    _readme(root, analyzer)
    _scripts(root, analyzer)
    _makefile(root, analyzer)
    _justfile(root, analyzer)
    _dockerfile(root, analyzer)
    _package_json(root, analyzer, out)
    _setup_py(root, analyzer, out)
    _pyproject(root, analyzer, out)
    _requirements(root, out)
