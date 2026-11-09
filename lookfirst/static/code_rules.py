"""Rules for Python and JavaScript files that run during install. Read, never run.

- setup.py is read with Python's own parser (ast). It's never imported, so none of its
  code runs. Shell commands it passes to os.system or subprocess go through the shell
  rules; exec of decoded data and key theft are caught here.
- JavaScript run by npm lifecycle scripts gets pattern checks (lookfirst has no
  JavaScript parser): keys or passwords plus network calls, and eval of decoded data.
"""

from __future__ import annotations

import ast
import re
import shlex
from dataclasses import dataclass

from lookfirst.static.model import Collector, Origin, Snippet
from lookfirst.static.shell_rules import credential_kind

_SHELL_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "commands.getoutput",
}
_DECODERS = re.compile(
    r"b64decode|decodebytes|a85decode|b32decode|fromhex|decompress|codecs\.decode|marshal\.loads|unhexlify"
)
_PY_NETWORK = re.compile(
    r"\burllib\b|\brequests\.|http\.client|\bsocket\b|\bhttpx\b|\baiohttp\b|smtplib|ftplib"
)
_JS_NETWORK = re.compile(
    r"require\(\s*['\"](?:node:)?(?:https?|net|dgram|tls|dns)['\"]\s*\)|from\s+['\"](?:node:)?(?:https?|net|dgram|tls)['\"]"
    r"|\bfetch\(|\baxios\b|XMLHttpRequest|WebSocket|\.request\(\s*\{"
)
_JS_DECODE_RUN = re.compile(
    r"(?:\beval\s*\(|new\s+Function\s*\(|vm\.run\w*\s*\()[^;\n]{0,200}(?:atob\(|Buffer\.from\([^)]*['\"](?:base64|hex)['\"])"
    r"|(?:atob\(|Buffer\.from\([^)]*['\"](?:base64|hex)['\"])[^;\n]{0,200}(?:\beval\s*\(|new\s+Function\s*\()"
)
_JS_EXEC = re.compile(
    r"\b(?:exec|execSync|spawnSync|spawn)\s*\(\s*(['\"`])((?:(?!\1)[^\\\n]|\\.){1,500})\1"
)
_STRING = re.compile(r"(['\"`])((?:(?!\1)[^\\\n]|\\.){1,400})\1")


@dataclass
class CodeResult:
    shell: list[Snippet]  # shell commands found in the code, for the shell rules
    install_hook: bool  # setup.py customizes install (cmdclass)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _strings(node: ast.AST) -> list[str]:
    return [
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _credentials_and_network(
    text: str, strings: list[str], network: re.Pattern[str]
) -> tuple[str | None, bool]:
    kinds = [k for s in strings if (k := credential_kind(s))]
    if not kinds:
        # paths built in pieces, like os.path.join(home, ".ssh", "id_rsa")
        squashed = re.sub(r"['\"]\s*,\s*['\"]|['\"]\s*\+\s*['\"]", "/", text)
        kinds = [
            k
            for m in re.finditer(
                r"~?/?\.(?:ssh|aws|npmrc|netrc|docker|kube|gnupg|config/gh)[^'\"\s]*", squashed
            )
            if (k := credential_kind("~/" + m.group(0).lstrip("~/")))
        ]
    return (kinds[0] if kinds else None), bool(network.search(text))


def analyze_python(text: str, origin: Origin, out: Collector, *, is_setup_py: bool) -> CodeResult:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        out.add("install_path.unparsed", path=origin.path, line=origin.line, runs=origin.runs)
        return CodeResult([], False)
    shell: list[Snippet] = []
    install_hook = False
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "cmdclass" and is_setup_py:
            install_hook = True
        if isinstance(node, ast.ClassDef) and is_setup_py:
            bases = {_dotted(b).rsplit(".", 1)[-1] for b in node.bases}
            if bases & {
                "install",
                "develop",
                "egg_info",
                "build_py",
                "build_ext",
                "sdist",
                "bdist_wheel",
            }:
                install_hook = True
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        line = origin.line + node.lineno - 1
        if name in _SHELL_CALLS and node.args:
            first = node.args[0]
            command = None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                command = first.value
            elif isinstance(first, (ast.List, ast.Tuple)) and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) for e in first.elts
            ):
                command = shlex.join([e.value for e in first.elts])  # type: ignore[attr-defined]
            if command:
                shell.append(
                    Snippet(
                        command, Origin(origin.path, line, origin.runs, origin.remote, origin.depth)
                    )
                )
        if name in ("exec", "eval", "builtins.exec", "builtins.eval") and node.args:
            source = ast.unparse(node.args[0])
            if _DECODERS.search(source) or ("compile(" in source and _DECODERS.search(source)):
                out.add(
                    "install_path.decode_and_run",
                    path=origin.path,
                    line=line,
                    excerpt=ast.unparse(node)[:200],
                    runs=origin.runs,
                )
    kind, network = _credentials_and_network(text, _strings(tree), _PY_NETWORK)
    if kind:
        rule = "install_path.credential_theft" if network else "install_path.credential_read"
        out.add(rule, path=origin.path, line=origin.line, runs=origin.runs, data={"what": kind})
    return CodeResult(shell, install_hook)


def analyze_javascript(text: str, origin: Origin, out: Collector) -> CodeResult:
    strings = [m.group(2) for m in _STRING.finditer(text)]
    kind, network = _credentials_and_network(text, strings, _JS_NETWORK)
    if kind:
        rule = "install_path.credential_theft" if network else "install_path.credential_read"
        out.add(rule, path=origin.path, line=origin.line, runs=origin.runs, data={"what": kind})
    for m in _JS_DECODE_RUN.finditer(text):
        line = origin.line + text.count("\n", 0, m.start())
        out.add(
            "install_path.decode_and_run",
            path=origin.path,
            line=line,
            excerpt=m.group(0)[:200],
            runs=origin.runs,
        )
    shell = []
    for m in _JS_EXEC.finditer(text):
        line = origin.line + text.count("\n", 0, m.start())
        shell.append(
            Snippet(
                m.group(2),
                Origin(origin.path, line, origin.runs, origin.remote, origin.depth),
                report_unparsed=False,
            )
        )
    return CodeResult(shell, False)
