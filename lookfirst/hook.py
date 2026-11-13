"""`lookfirst hook`: a PreToolUse hook for Claude Code's Bash tool (SPEC section 10).

Claude Code runs this before every shell command its agent runs. Most commands aren't
installs, so the first job is to say so quickly. This module imports only the Python
standard library (tests/test_hook.py checks), and the full check in hook_run.py is loaded
only when a command looks like it installs something or runs downloaded code.

The answer goes back as JSON on stdout, and the exit code is always 0. Exit 2 would block
the command without a proper reason, and any other code is reported as a broken hook. If
anything goes wrong, the command is let through with a visible warning, so a broken hook
never stops the agent from working (PLAN decision 3, 5 Nov 2026).

The command is untrusted: an agent may have copied it from a README written to fool it.
It's only read here, never run.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sys
import time
from io import BufferedIOBase

# Only the standard library, and not even all of it: dataclasses, typing and
# collections.abc each add milliseconds to every command the agent runs.

MAX_INPUT = 1024 * 1024  # bytes of hook JSON read from stdin
MAX_TARGETS = 5
BUDGET_SECONDS = 20.0  # SPEC: the static check gets 20 seconds; Claude Code waits 30
FRESH_CLONE_SECONDS = 24 * 3600  # M6 decision 4
_MAX_LEVEL = 5  # how deep $(...) and bash -c "..." are followed
_DYNAMIC = "$(…)"  # stands in for a substitution inside a word

USAGE = """\
Usage: lookfirst hook

Claude Code's PreToolUse hook for the Bash tool. It reads the hook's JSON on stdin and
checks commands that install something or run downloaded code before they run. Most
commands aren't checked at all. The lookfirst plugin sets it up, or add it to a
settings.json file yourself:

  {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": "lookfirst hook", "timeout": 30}]}]}}
"""

TOO_BIG = "lookfirst didn't check this command: it's too long to read (over 1 MB)."
BROKEN = (
    "lookfirst ran into a problem and didn't check this command. "
    "If this keeps happening, please report it."
)

SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "fish", "busybox"})
INTERPRETERS = frozenset(
    {"python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "node", "nodejs"}
    | {"deno", "php", "osascript", "lua"}
)
CODE_RUNNERS = SHELLS | INTERPRETERS | {"eval", "source", "."}
DOWNLOADERS = frozenset(
    {"curl", "wget", "wget2", "fetch", "aria2c", "http", "https", "xh", "xhs", "lwp-request"}
)
_WRAPPERS = frozenset(
    {"sudo", "doas", "pkexec", "run0", "env", "nohup", "exec", "builtin", "time", "nice"}
    | {"ionice", "caffeinate", "stdbuf", "unbuffer", "chronic", "timeout", "gtimeout"}
)
_WRAPPER_VALUES = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T", "--user", "--group"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-t"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "gtimeout": {"-s", "-k", "--signal", "--kill-after"},
}
_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!"})
_KEYWORDS |= {"{", "}", "[[", "]]"}
_HEADERS = frozenset({"for", "case", "select", "function", "esac"})  # not commands that run
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
_PYTHON = re.compile(r"^(?:python|pypy)(\d+(?:\.\d+)*)?$")
_PIP = re.compile(r"^pip(\d+(?:\.\d+)*)?$")
# A quick look before reading the command properly: no word here means nothing to check.
_TRIGGERS = re.compile(
    r"curl|wget|fetch|aria2c|\bhttps?\b|\bxhs?\b|lwp|base64|xxd|openssl|uudecode|\.sh\b"
    r"|\bpip|\buv\b|\buvx\b|\bpipx\b|\bpoetry\b|\bpipenv\b|\bnpm\b|\bnpx\b|\bpnpm\b|\byarn\b"
    r"|\bbunx?\b|\bgit\b|\bgh\b|install|setup|\bmake\b|\./|\bsource\b|(?:^|[\s;&|(])\.\s"
)


# --- reading the command ----------------------------------------------------


class _Cmd:
    """One simple command, like `curl -fsSL https://x` in `curl -fsSL https://x | sh`."""

    __slots__ = ("heredoc", "level", "parent", "pipeline", "position", "words", "writes_file")

    def __init__(
        self,
        words: list[str],
        level: int,  # 0 for the command line itself, 1 inside its $(...) or bash -c "..."
        parent: int | None,  # the command whose $(...), <(...) or -c string holds this one
        pipeline: int,  # commands joined by | share a pipeline
        position: int,  # place in its pipeline, from 0
        heredoc: str | None = None,  # a here-document's or here-string's text
        writes_file: bool = False,  # its output is redirected to a file
    ) -> None:
        self.words = words
        self.level = level
        self.parent = parent
        self.pipeline = pipeline
        self.position = position
        self.heredoc = heredoc
        self.writes_file = writes_file


def _matching(text: str, start: int) -> int:
    """The index of the ")" closing the "(" at start, or len(text) if it never closes."""
    depth, i, n = 0, start, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "'":
            end = text.find("'", i + 1)
            i = n if end < 0 else end + 1
            continue
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 2
                elif text.startswith("$(", i):
                    i = _matching(text, i + 1) + 1
                else:
                    i += 1
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _closing_backtick(text: str, start: int) -> int:
    i, n = start, len(text)
    while i < n and text[i] != "`":
        i += 2 if text[i] == "\\" else 1
    return min(i, n)


class _Lexer:
    """Splits shell text into simple commands the way bash would, without running anything.

    It's good enough to tell what kind of command this is: quotes, escapes, pipes, &&, ||,
    ;, subshells, $(...), backticks, <(...), here-documents and here-strings. Code inside
    $(...), <(...) and bash -c "..." becomes commands of its own, one level down. The full
    check reads the command again with a real shell parser (tree-sitter).
    """

    def __init__(self) -> None:
        self.cmds: list[_Cmd] = []
        self._pipelines = 0

    def _new_pipeline(self) -> int:
        self._pipelines += 1
        return self._pipelines

    def parse(self, text: str, level: int = 0, parent: int | None = None) -> None:
        if level > _MAX_LEVEL:
            return
        n, i = len(text), 0
        words: list[str] = []
        buf: list[str] = []
        in_word = False
        nested: list[str] = []
        state = {"target": False, "herestring": False, "writes": False}
        heredoc_text: list[str | None] = [None]
        own_heredocs: list[tuple[str, bool]] = []
        waiting: list[tuple[int, str, bool]] = []
        pipeline, position = self._new_pipeline(), 0

        def end_word() -> None:
            nonlocal in_word
            if not in_word:
                return
            word = "".join(buf)
            buf.clear()
            in_word = False
            if state["herestring"]:
                state["herestring"] = False
                heredoc_text[0] = word
            elif state["target"]:
                state["target"] = False
                if word not in ("/dev/null", "/dev/stderr", "/dev/stdout") and not (
                    word.isdigit() or word == "-"
                ):
                    state["writes"] = state["writes"] or state.get("out", False)
            else:
                words.append(word)

        def end_command(pipe: bool) -> None:
            nonlocal pipeline, position
            end_word()
            kept = _strip_keywords(words)
            if kept or nested or heredoc_text[0] is not None or own_heredocs:
                index = len(self.cmds)
                self.cmds.append(
                    _Cmd(
                        kept,
                        level,
                        parent,
                        pipeline,
                        position,
                        heredoc_text[0],
                        bool(state["writes"]),
                    )
                )
                waiting.extend((index, d, s) for d, s in own_heredocs)
                for inner in list(nested):
                    self.parse(inner, level + 1, index)
                position += 1
            words.clear()
            nested.clear()
            own_heredocs.clear()
            heredoc_text[0] = None
            state.update(target=False, herestring=False, writes=False, out=False)
            if not pipe:
                pipeline, position = self._new_pipeline(), 0

        def read_bodies() -> None:
            nonlocal i
            for index, delimiter, strip in waiting:
                lines: list[str] = []
                while i < n:
                    end = text.find("\n", i)
                    line = text[i:] if end < 0 else text[i:end]
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip else line) == delimiter:
                        break
                    lines.append(line)
                self.cmds[index].heredoc = "\n".join(lines)
            waiting.clear()

        while i < n:
            ch = text[i]
            if ch == "\\":
                if i + 1 < n and text[i + 1] != "\n":
                    buf.append(text[i + 1])
                    in_word = True
                i += 2
            elif ch == "'":
                end = text.find("'", i + 1)
                end = n if end < 0 else end
                buf.append(text[i + 1 : end])
                in_word = True
                i = end + 1
            elif ch == "$" and text.startswith("$'", i):
                end = i + 2
                while end < n and text[end] != "'":
                    end += 2 if text[end] == "\\" else 1
                buf.append(text[i + 2 : end])
                in_word = True
                i = end + 1
            elif ch == '"':
                i = self._double_quoted(text, i + 1, buf, nested)
                in_word = True
            elif ch == "`":
                end = _closing_backtick(text, i + 1)
                nested.append(text[i + 1 : end])
                buf.append(_DYNAMIC)
                in_word = True
                i = end + 1
            elif ch == "$" and text.startswith("$((", i):
                buf.append("0")  # arithmetic
                in_word = True
                i = _matching(text, i + 1) + 1
            elif ch == "$" and text.startswith("$(", i):
                end = _matching(text, i + 1)
                nested.append(text[i + 2 : end])
                buf.append(_DYNAMIC)
                in_word = True
                i = end + 1
            elif ch in "<>" and text.startswith("(", i + 1) and not in_word:
                end = _matching(text, i + 1)
                nested.append(text[i + 2 : end])
                buf.append(f"{ch}(…)")
                in_word = True
                i = end + 1
            elif ch == "#" and not in_word:
                end = text.find("\n", i)
                i = n if end < 0 else end
            elif ch in " \t":
                end_word()
                i += 1
            elif ch == "\n":
                end_command(pipe=False)
                i += 1
                read_bodies()
            elif ch == ";":
                end_command(pipe=False)
                i += 1
                while i < n and text[i] in ";&":
                    i += 1
            elif ch == "&":
                if text.startswith("&&", i):
                    end_command(pipe=False)
                    i += 2
                elif text.startswith("&>", i):
                    end_word()
                    i += 3 if text.startswith("&>>", i) else 2
                    state.update(target=True, out=True)
                else:
                    end_command(pipe=False)
                    i += 1
            elif ch == "|":
                if text.startswith("||", i):
                    end_command(pipe=False)
                    i += 2
                else:
                    end_command(pipe=True)
                    i += 2 if text.startswith("|&", i) else 1
            elif ch in "()":
                end_command(pipe=False)
                i += 1
            elif ch in "<>":
                if in_word and "".join(buf).isdigit():
                    buf.clear()
                    in_word = False
                else:
                    end_word()
                if text.startswith("<<<", i):
                    state["herestring"] = True
                    i += 3
                elif text.startswith("<<", i):
                    strip = text.startswith("<<-", i)
                    i += 3 if strip else 2
                    while i < n and text[i] in " \t":
                        i += 1
                    start = i
                    while i < n and text[i] not in " \t\n;&|<>()":
                        i += 1
                    delimiter = re.sub(r"[\"'\\]", "", text[start:i])
                    own_heredocs.append((delimiter, strip))
                else:
                    out = ch == ">"
                    i += 1
                    while i < n and text[i] in ">|&":
                        i += 1
                    state.update(target=True, out=out)
            else:
                buf.append(ch)
                in_word = True
                i += 1
        end_command(pipe=False)
        read_bodies()

    @staticmethod
    def _double_quoted(text: str, i: int, buf: list[str], nested: list[str]) -> int:
        n = len(text)
        while i < n:
            ch = text[i]
            if ch == '"':
                return i + 1
            if ch == "\\" and i + 1 < n:
                if text[i + 1] in '"\\$`':
                    buf.append(text[i + 1])
                elif text[i + 1] != "\n":
                    buf.append("\\" + text[i + 1])
                i += 2
            elif text.startswith("$((", i):
                buf.append("0")
                i = _matching(text, i + 1) + 1
            elif text.startswith("$(", i):
                end = _matching(text, i + 1)
                nested.append(text[i + 2 : end])
                buf.append(_DYNAMIC)
                i = end + 1
            elif ch == "`":
                end = _closing_backtick(text, i + 1)
                nested.append(text[i + 1 : end])
                buf.append(_DYNAMIC)
                i = end + 1
            else:
                buf.append(ch)
                i += 1
        return n


def _strip_keywords(words: list[str]) -> list[str]:
    start = 0
    while start < len(words) and words[start] in _KEYWORDS:
        start += 1
    if start < len(words) and words[start] in _HEADERS:
        return []
    return words[start:]


def read_commands(command: str) -> list[_Cmd]:
    """Every simple command in a command line, including those inside $(...), <(...),
    bash -c "..." and eval, and here-documents fed to a shell."""
    lexer = _Lexer()
    lexer.parse(command)
    done = 0
    while done < len(lexer.cmds):  # code handed to a shell becomes commands of its own
        cmd = lexer.cmds[done]
        index = done
        done += 1
        if cmd.level >= _MAX_LEVEL:
            continue
        rest = peel(cmd.words)
        name = program(rest[0]) if rest else ""
        inner = None
        if name in SHELLS:
            for k, word in enumerate(rest[1:-1], start=1):
                if word == "-c" or (word[:1] == "-" and word[1:2] != "-" and "c" in word):
                    inner = rest[k + 1]
                    break
        elif name == "eval":
            inner = " ".join(rest[1:])
        if inner:  # substitutions inside it were already read as commands of their own
            lexer.parse(inner.replace(_DYNAMIC, "$DYNAMIC"), cmd.level + 1, index)
        later = [
            c
            for c in lexer.cmds
            if c.pipeline == cmd.pipeline and c.position > cmd.position and c.level == cmd.level
        ]
        if cmd.heredoc and (name in CODE_RUNNERS or any(_runs_code(c) for c in later)):
            lexer.parse(cmd.heredoc, cmd.level + 1, index)
        if "--" in rest:  # `claude mcp add name -- npx -y pkg`: the command after --
            tail = rest[rest.index("--") + 1 :]
            if tail and program(tail[0]) in _RUNNER_NAMES:
                lexer.cmds.append(_Cmd(tail, cmd.level + 1, index, -index - 1, 0))
    return lexer.cmds


# --- what each command is ----------------------------------------------------


def program(word: str) -> str:
    """A command's program name: `/usr/bin/python3.12` is python3, `pip3.12` is pip. macOS
    finds programs whatever their case, so `CURL ... | BASH` is curl piped into bash."""
    name = posixpath.basename(word).lower()
    if _PYTHON.match(name):
        return "python3" if name not in ("python", "python2") else name
    if _PIP.match(name):
        return "pip"
    return name


def peel(words: list[str]) -> list[str]:
    """The command without what wraps it: `sudo -E env X=1 bash` is `bash`."""
    i = 0
    while i < len(words):
        word = words[i]
        if _ASSIGNMENT.match(word):
            i += 1
            continue
        name = posixpath.basename(word).lower()
        if name == "command" and i + 1 < len(words) and words[i + 1] in ("-v", "-V"):
            return []  # `command -v x` only asks where x is
        if name not in _WRAPPERS and name != "command":
            break
        i += 1
        values = _WRAPPER_VALUES.get(name, set())
        while i < len(words) and words[i].startswith("-") and words[i] != "--":
            i += 2 if words[i] in values else 1
        if i < len(words) and words[i] == "--":
            i += 1
        if name in ("timeout", "gtimeout") and i < len(words):
            i += 1  # the time limit
    return words[i:]


def _name_and_args(cmd: _Cmd) -> tuple[str, list[str], list[str]]:
    rest = peel(cmd.words)
    if not rest:
        return "", [], rest
    return program(rest[0]), rest[1:], rest


def _runs_code(cmd: _Cmd) -> bool:
    name, _, _ = _name_and_args(cmd)
    return name in CODE_RUNNERS


def _is_decoder(name: str, args: list[str]) -> bool:
    if name == "base64":
        return any(
            a in ("-d", "-D", "--decode") or (a[:1] == "-" and a[1:2] != "-" and "d" in a)
            for a in args
        )
    if name == "openssl":
        return ("base64" in args or "enc" in args) and ("-d" in args or "-a" in args)
    if name == "xxd":
        return any(a.startswith("-r") for a in args)
    if name in ("uudecode", "gunzip", "zcat", "bzcat", "unxz", "xzcat"):
        return True
    return name in ("gzip", "xz", "bzip2", "zstd") and any(
        a in ("-d", "--decompress", "-dc", "-cd") for a in args
    )


def _saves_download(name: str, args: list[str], cmd: _Cmd) -> bool:
    if name not in DOWNLOADERS:
        return False
    if cmd.writes_file:
        return True
    if name in ("wget", "wget2"):  # wget saves to a file unless told to print
        to_stdout = any(a in ("-O-", "-qO-", "--output-document=-") for a in args) or any(
            a in ("-O", "-qO") and args[k + 1 : k + 2] == ["-"] for k, a in enumerate(args)
        )
        return not to_stdout
    return any(
        a in ("-o", "-O", "--output", "--remote-name", "--remote-name-all")
        or a.startswith("--output=")
        or (a[:1] == "-" and a[1:2] != "-" and ("o" in a or "O" in a))
        for a in args
    )


def _runs_a_file(name: str, args: list[str], rest: list[str]) -> bool:
    first = rest[0] if rest else ""
    temporary = ("/tmp/", "/var/tmp/")  # noqa: S108 - places downloads are often run from
    if first.startswith(("./", "../", "~/", "$HOME", _DYNAMIC, *temporary)):
        return True
    if name in CODE_RUNNERS and any(not a.startswith("-") for a in args):
        return True
    if name == "chmod" and any(re.search(r"x|^[0-7]{3,4}$", a) for a in args):
        return True
    return name in ("open", "installer", "hdiutil")


# --- what to check -------------------------------------------------------------


class Planned:
    """Something to check: what `lookfirst check` is given, and what kind of thing it is."""

    __slots__ = ("kind", "target")

    def __init__(self, target: str, kind: str) -> None:
        self.target = target
        self.kind = kind  # "command", "package", "repo" or "folder"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Planned) and (self.target, self.kind) == (other.target, other.kind)

    def __hash__(self) -> int:
        return hash((self.target, self.kind))

    def __repr__(self) -> str:
        return f"Planned({self.target!r}, {self.kind!r})"


def plan_checks(command: str, cwd: str, *, now: float | None = None) -> list[Planned]:
    """What to check before this command runs. An empty list means nothing to check."""
    if not _TRIGGERS.search(command.lower()):
        return []
    cmds = read_commands(command)
    info = [_name_and_args(c) for c in cmds]
    plans: list[Planned] = []

    def add(target: str, kind: str) -> None:
        if len(plans) < MAX_TARGETS and all(p.target != target for p in plans):
            plans.append(Planned(target, kind))

    if _runs_downloaded_code(cmds, info):
        add(command.strip(), "command")
    folders = _folders(cmds, info, cwd)
    fresh: dict[str, str | None] = {}
    clock = time.time() if now is None else now

    def fresh_root(folder: str | None) -> str | None:
        if folder is None:
            return None
        if folder not in fresh:
            fresh[folder] = fresh_clone_root(folder, clock)
        return fresh[folder]

    for index, (name, args, rest) in enumerate(info):
        if not name:
            continue
        folder = folders[index]
        runner = _runner_target(name, args, rest, folder)
        if runner:
            add(runner, "package")
            continue
        installs = _install_targets(name, args)
        if installs:
            for kind, value in installs:
                if kind == "local":
                    root = fresh_root(_join(folder, value))
                    if root:
                        add(root, "folder")
                else:
                    add(value, kind)
            continue
        where = _installer_folder(name, args, rest)
        if where is not None:
            root = fresh_root(_join(folder, where))
            if root:
                add(root, "folder")
    for repo in _cloned_then_used(cmds, info):
        add(repo, "repo")
    return plans


def _runs_downloaded_code(cmds: list[_Cmd], info: list[tuple[str, list[str], list[str]]]) -> bool:
    downloads = {i for i, (name, _, _) in enumerate(info) if name in DOWNLOADERS}
    fetchers = downloads | {i for i, (name, args, _) in enumerate(info) if _is_decoder(name, args)}
    if not fetchers:
        return False
    children: dict[int, list[int]] = {}
    for i, c in enumerate(cmds):
        if c.parent is not None:
            children.setdefault(c.parent, []).append(i)

    def inside(i: int) -> set[int]:
        found, todo = set(), list(children.get(i, []))
        while todo:
            j = todo.pop()
            if j not in found:
                found.add(j)
                todo.extend(children.get(j, []))
        return found

    for i, (name, args, _) in enumerate(info):
        if name not in CODE_RUNNERS:
            continue
        c = cmds[i]
        earlier = {
            j for j, o in enumerate(cmds) if o.pipeline == c.pipeline and o.position < c.position
        }
        if earlier & fetchers or inside(i) & fetchers:
            return True  # curl ... | sh, bash <(curl ...), sh -c "$(curl ...)"
        if downloads and any("$" in a or a == _DYNAMIC for a in args):
            return True  # eval "$script" after a download
    for d in downloads:  # curl -o x.sh ... && bash x.sh
        name, args, _ = info[d]
        if _saves_download(name, args, cmds[d]) and any(
            _runs_a_file(*info[j]) for j in range(d + 1, len(cmds))
        ):
            return True
    return False


def _folders(
    cmds: list[_Cmd], info: list[tuple[str, list[str], list[str]]], cwd: str
) -> list[str | None]:
    """The folder each command runs in, following `cd` in the command line itself and in
    code handed to a shell, like `bash -c 'cd repo && ./install.sh'`."""
    scopes: dict[int | None, str | None] = {None: cwd}  # by the command that holds the code
    result: list[str | None] = []
    for c, (name, args, _) in zip(cmds, info, strict=True):
        scope = c.parent if c.level > 0 else None
        if scope not in scopes:  # code inside a command starts where that command runs
            scopes[scope] = result[scope] if scope is not None else cwd
        folder = scopes[scope]
        if name in ("cd", "pushd"):
            target = next((a for a in args if not a.startswith("-")), "")
            folder = _join(folder, target) if target and target != "-" else None
            scopes[scope] = folder
        result.append(folder)
    return result


def _join(folder: str | None, path: str) -> str | None:
    if folder is None or "$" in path or "…" in path:
        return None
    return posixpath.normpath(posixpath.join(folder, os.path.expanduser(path)))


# Package runners: they download a package and run it in one go.
_RUNNER_NAMES = frozenset({"npx", "bunx", "uvx", "pnpm", "yarn", "bun", "pipx", "uv", "npm"})
_NPX_VALUES = frozenset({"--package", "-p", "--registry", "--cache", "--userconfig", "-c"})


def _runner_target(name: str, args: list[str], rest: list[str], folder: str | None) -> str | None:
    """The command to give `lookfirst check` for `npx -y pkg`, `uvx pkg` and the like."""
    words = rest
    npm_like = (
        name in ("npx", "bunx")
        or (name in ("pnpm", "yarn") and args[:1] == ["dlx"])
        or (name == "bun" and args[:1] == ["x"])
    )
    if name == "npm" and args[:1] in (["exec"], ["x"]):
        words = ["npx", "--yes", *[a for a in args[1:] if a not in ("-y", "--yes")]]
        npm_like = True
    python_like = (
        name == "uvx"
        or (name == "uv" and args[:2] == ["tool", "run"])
        or (name == "pipx" and args[:1] == ["run"])
    )
    if not (npm_like or python_like):
        return None
    if npm_like and folder is not None:
        package = _first_positional(words[1:], _NPX_VALUES)
        if package and "/" not in package.lstrip("@").split("@")[0]:
            local = posixpath.join(folder, "node_modules", ".bin", package.split("@")[0])
            if os.path.exists(local):
                return None  # the project's own copy, already installed
    return " ".join(_quote(w) for w in words)


def _first_positional(args: list[str], values: frozenset[str]) -> str | None:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-"):
            i += 2 if a in values else 1
            continue
        return a
    return None


def _quote(word: str) -> str:
    if word and re.fullmatch(r"[A-Za-z0-9@%+=:,./_-]+", word):
        return word
    return "'" + word.replace("'", "'\"'\"'") + "'"


# Package installs: `pip install x`, `npm install y` and their relatives.
_NPM_INSTALL = frozenset(
    {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal"}
    | {"isntall", "add"}
)
_PIP_VALUES = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url"}
    | {"--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root"}
    | {"--src", "--python", "-p", "--group", "--extra", "--optional", "--index"}
    | {"--default-index", "--upgrade-package", "-P", "--with", "--with-requirements"}
    | {"--with-editable", "--spec", "--suffix", "--pip-args", "--platform", "--abi"}
    | {"--python-version", "--implementation", "--config-settings", "-C", "--log"}
    | {"--cache-dir", "--progress-bar", "--report", "--only-binary", "--no-binary"}
    | {"--trusted-host", "--proxy", "--retries", "--timeout", "--exists-action"}
    | {"--python-platform", "--package", "--script", "--branch", "--tag", "--rev"}
    | {"--marker", "-m", "--bounds", "--directory", "--project"}
)
_NPM_VALUES = frozenset(
    {"--registry", "--prefix", "-C", "--dir", "--cwd", "--workspace", "-w", "--tag"}
    | {"--cache", "--userconfig", "--filter", "--loglevel", "--omit", "--include"}
    | {"--install-strategy", "--before", "--network-concurrency", "--modules-folder"}
)
_PEP508 = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*"
    r"(?:===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)\s*)?(?:$|[;,<>~!=\s])"
)
_NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*$")
_NPM_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_GITHUB = re.compile(
    r"(?:^|[/@:+])github\.com[/:]([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:[/#@?]|$)"
)
_GITHUB_SHORT = re.compile(r"^(?:github:)?([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})(?:#.*)?$")


def _install_target_words(name: str, args: list[str]) -> tuple[str, list[str]] | None:
    """("pypi" or "npm", the words after the install verb), for package installs."""
    words = list(args)
    while words and words[0].startswith("-"):  # uv --quiet pip install ..., npm --prefix x i
        option = words.pop(0)
        if option in _FOLDER_VALUES and words:
            words.pop(0)
    if name == "pip" and words[:1] == ["install"]:
        return "pypi", words[1:]
    if name in ("python", "python3") and "-m" in args:
        after = args[args.index("-m") + 1 :]
        if after[:2] == ["pip", "install"]:
            return "pypi", after[2:]
    if name == "uv":
        if words[:2] == ["pip", "install"]:
            return "pypi", words[2:]
        if words[:1] == ["add"]:
            return "pypi", words[1:]
        if words[:2] == ["tool", "install"]:
            return "pypi", words[2:]
    if (name, words[:1]) in (("pipx", ["install"]), ("poetry", ["add"]), ("pipenv", ["install"])):
        return "pypi", words[1:]
    if name == "npm" and words[:1] and words[0] in _NPM_INSTALL:
        return "npm", words[1:]
    if name in ("pnpm", "bun") and words[:1] in (["add"], ["install"], ["i"]):
        return "npm", words[1:]
    if name == "yarn" and words[:1] == ["add"]:
        return "npm", words[1:]
    return None


def _install_targets(name: str, args: list[str]) -> list[tuple[str, str]] | None:
    """[(kind, target)] for each package an install command names. kind is "package",
    "repo", or "local" (a path; it's checked if it's in a freshly cloned folder). None if
    this isn't a package install; an empty list if it installs only the project itself."""
    found = _install_target_words(name, args)
    if found is None:
        return None
    ecosystem, words = found
    values = _PIP_VALUES if ecosystem == "pypi" else _NPM_VALUES
    targets: list[tuple[str, str]] = []
    i = 0
    while i < len(words):
        word = words[i]
        option, eq, inline = word.partition("=")
        if word.startswith("-") and option in values:
            value = inline if eq else (words[i + 1] if i + 1 < len(words) else "")
            i += 1 if eq else 2
            if option in ("-r", "--requirement", "--with-requirements") and value:
                targets.append(("local", posixpath.dirname(value) or "."))
            elif option in ("-e", "--editable", "--with-editable") and value:
                targets.extend(_editable(value))
            continue
        i += 1
        if word.startswith("-"):
            continue
        targets.extend(_one_install(ecosystem, word))
    return targets


def _editable(value: str) -> list[tuple[str, str]]:
    """An editable install is always a folder or a repo, never a registry package."""
    m = _GITHUB.search(value)
    if m:
        return [("repo", f"{m.group(1)}/{m.group(2)}")]
    if "://" in value or value.startswith("git+") or "$" in value:
        return []
    return [("local", value.removeprefix("file:"))]


def _one_install(ecosystem: str, word: str) -> list[tuple[str, str]]:
    if not word or "…" in word or "$" in word:
        return []
    if word in (".", "..") or word.startswith(("./", "../", "/", "~", "file:")):
        return [("local", word.removeprefix("file:"))]
    m = _GITHUB.search(word)
    if m:
        return [("repo", f"{m.group(1)}/{m.group(2)}")]
    if "://" in word or word.startswith("git+"):
        return []  # an archive or another git host: not something lookfirst checks yet
    if ecosystem == "pypi":
        if "/" in word or word.endswith((".whl", ".tar.gz", ".zip")):
            return [("local", posixpath.dirname(word) or ".")]
        m = _PEP508.match(word)
        if not m:
            return []
        return [("package", f"pypi:{m.group(1)}" + (f"=={m.group(2)}" if m.group(2) else ""))]
    short = _GITHUB_SHORT.match(word)
    if short and not word.startswith("@"):
        return [("repo", f"{short.group(1)}/{short.group(2)}")]
    if "@npm:" in word:  # an alias: name@npm:real@version
        word = word.split("@npm:", 1)[1]
    name, at, version = word.rpartition("@") if word.rfind("@") > 0 else (word, "", "")
    if not _NPM_NAME.match(name):
        return []
    exact = at and _NPM_VERSION.match(version)
    return [("package", f"npm:{name}" + (f"@{version}" if exact else ""))]


_INSTALL_SCRIPT = re.compile(r"^(?:install|setup|bootstrap)[^/]*\.(?:py|js|mjs|cjs|rb|pl|php)$")


# Options that name the folder a command works in: make -C, npm --prefix, yarn --cwd, ...
_FOLDER_VALUES = frozenset(
    {"--prefix", "-C", "--dir", "--cwd", "--directory", "--project", "--workspace", "-w"}
)


def _positionals(args: list[str]) -> tuple[list[str], str | None]:
    """The words that aren't options, and the folder an option like -C or --prefix names."""
    words: list[str] = []
    where = None
    i = 0
    while i < len(args):
        word = args[i]
        option, eq, value = word.partition("=")
        if word.startswith("-") and option in _FOLDER_VALUES:
            where = value if eq else (args[i + 1] if i + 1 < len(args) else None)
            i += 1 if eq else 2
            continue
        if not word.startswith("-"):
            words.append(word)
        i += 1
    return words, where


def _installer_folder(name: str, args: list[str], rest: list[str]) -> str | None:
    """Where a command runs a project's own installer from, relative to where it runs:
    "." for make or a bare npm install, the script's own folder for `bash repo/install.sh`
    or `./install.sh`, the folder an option names for `make -C repo` or
    `npm --prefix repo install`. None if it doesn't run one."""
    if name in SHELLS | {"source", "."}:
        if any(a == "-c" or (a[:1] == "-" and a[1:2] != "-" and "c" in a) for a in args):
            return None  # the code after -c is read as commands of its own
        script = next((a for a in args if not a.startswith("-")), None)
        return None if script is None else (posixpath.dirname(script) or ".")
    if name in INTERPRETERS:
        script = next((a for a in args if not a.startswith("-")), "")
        if _INSTALL_SCRIPT.match(posixpath.basename(script)):
            return posixpath.dirname(script) or "."
        return None
    words, where = _positionals(args)
    folder = where or "."
    if name == "make":
        return folder
    if name == "npm":
        # a bare `npm link` installs the folder globally, running its install scripts
        found = words in (["install"], ["i"], ["ci"], ["add"], ["link"], ["ln"])
    elif name in ("pnpm", "bun"):
        found = words in (["install"], ["i"])
    elif name == "yarn":
        found = not words or words == ["install"]
    elif name == "uv":
        found = words[:1] == ["sync"]
    elif name in ("poetry", "pipenv"):
        found = words == ["install"]
    else:  # a file run straight: ./install.sh, scripts/setup.sh, /path/to/repo/install.sh
        first = rest[0] if rest else ""
        return (posixpath.dirname(first) or ".") if "/" in first else None
    return folder if found else None


_SAFE_AFTER_CLONE = frozenset(
    {"cd", "pushd", "popd", "ls", "pwd", "echo", "printf", "cat", "less", "more", "head"}
    | {"tail", "git", "tree", "true", "false", ":", "sleep", "mkdir", "cp", "mv", "rm"}
    | {"touch", "grep", "rg", "find", "wc", "which", "type", "file", "stat", "du", "code"}
)
_CLONE_VALUES = frozenset(
    {"-b", "--branch", "--depth", "-o", "--origin", "--reference", "-c", "--config"}
    | {"--template", "--separate-git-dir", "-j", "--jobs", "--filter", "--shallow-since"}
    | {"--shallow-exclude", "-u", "--upload-pack", "--server-option", "--bundle-uri"}
)


def _cloned_then_used(cmds: list[_Cmd], info: list[tuple[str, list[str], list[str]]]) -> list[str]:
    """GitHub repos that are cloned and then installed or run in the same command line."""
    repos = []
    for i, (name, args, _) in enumerate(info):
        if cmds[i].level != 0:
            continue
        if name == "git" and args[:1] == ["clone"]:
            words = args[1:]
        elif name == "gh" and args[:2] == ["repo", "clone"]:
            words = args[2:]
        else:
            continue
        url = _first_positional(words, _CLONE_VALUES)
        if not url:
            continue
        m = _GITHUB.search(url) or (_GITHUB_SHORT.match(url) if name == "gh" else None)
        if not m:
            continue
        repo = f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
        branch = None
        for k, word in enumerate(words[:-1]):
            if word in ("-b", "--branch"):
                branch = words[k + 1]
        if branch and re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch):
            repo += f"@{branch}"
        later = [n for c, (n, _, _) in zip(cmds[i + 1 :], info[i + 1 :], strict=True) if n]
        if any(n not in _SAFE_AFTER_CLONE for n in later):
            repos.append(repo)
    return repos


def fresh_clone_root(folder: str, now: float) -> str | None:
    """The top folder of the git clone this folder is in, if it was cloned within the last
    24 hours (git's own record of the clone says when). None otherwise."""
    path = os.path.abspath(folder)
    for _ in range(40):
        dot_git = os.path.join(path, ".git")
        logs = None
        if os.path.isdir(dot_git):
            logs = os.path.join(dot_git, "logs", "HEAD")
        elif os.path.isfile(dot_git):
            try:
                with open(dot_git, encoding="utf-8", errors="replace") as f:
                    line = f.read(4096).strip()
            except OSError:
                return None
            if line.startswith("gitdir:"):
                gitdir = os.path.join(path, line.removeprefix("gitdir:").strip())
                logs = os.path.join(gitdir, "logs", "HEAD")
        if logs is not None:
            return path if _cloned_recently(logs, now) else None
        parent = os.path.dirname(path)
        if parent == path:
            return None
        path = parent
    return None


def _cloned_recently(logs: str, now: float) -> bool:
    try:
        with open(logs, encoding="utf-8", errors="replace") as f:
            first = f.readline(8192)
    except OSError:
        return False
    head, _, message = first.partition("\t")
    if not message.startswith("clone: from "):
        return False
    parts = head.rsplit(" ", 2)
    if len(parts) < 3 or not parts[1].isdigit():
        return False
    when = int(parts[1])
    return -300 <= now - when <= FRESH_CLONE_SECONDS


# --- talking to Claude Code ----------------------------------------------------


def _read_input(stream: BufferedIOBase) -> dict | None:
    raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise _TooBig
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


class _TooBig(Exception):
    pass


def _emit(answer: dict) -> None:
    sys.stdout.write(json.dumps(answer, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | tuple[str, ...] = ()) -> int:
    """Read Claude Code's hook input, decide, and answer. Always returns 0."""
    if any(a in ("-h", "--help") for a in argv):
        sys.stdout.write(USAGE)
        return 0
    started = time.monotonic()
    try:
        data = _read_input(sys.stdin.buffer)
        tool_input = data.get("tool_input") if data else None
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        if not isinstance(command, str) or not command.strip():
            return 0  # not a shell command: nothing for lookfirst to say
        cwd = data.get("cwd") if data else None
        cwd = cwd if isinstance(cwd, str) and cwd.startswith("/") else os.getcwd()
        plans = plan_checks(command, cwd)
    except _TooBig:
        _emit({"systemMessage": TOO_BIG})
        return 0
    except Exception:  # a broken hook must never stop the agent (decision 3)
        _emit({"systemMessage": BROKEN})
        return 0
    if not plans:
        return 0
    still_running = False
    try:
        from lookfirst.hook_run import answer

        result, still_running = answer(
            plans, cwd=cwd, budget=BUDGET_SECONDS - (time.monotonic() - started)
        )
    except Exception:
        result = {"systemMessage": BROKEN}
    if result:
        _emit(result)
    if still_running:  # a check is still going past the budget: leave without waiting for it
        sys.stdout.flush()
        os._exit(0)
    return 0
