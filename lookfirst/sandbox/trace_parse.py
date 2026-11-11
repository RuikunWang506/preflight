"""Reading strace's output from a sandbox run.

strace runs with `-f` (follow child processes), so lines start with a process id, and a
call interrupted by another process is split across an `<unfinished ...>` line and a
`<... resumed>` line. This parser stitches those together and keeps, for every process,
the program it's running and its current folder (from fork, chdir and execve), so a
relative `cat .ssh/id_ed25519` is still seen as reading the decoy key.

Everything here comes from the target: lines may be malformed or misleading, and a line
that doesn't parse is skipped.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

# The calls the sandbox traces. A regex, so names missing on one architecture (arm64 has
# no plain open, rename or unlink) aren't an error.
TRACE_CALLS = (
    "execve|execveat|open|openat|openat2|creat|connect|rename|renameat|renameat2"
    "|unlink|unlinkat|chdir|fchdir|clone|clone3|fork|vfork"
)
STRACE_FILTER = f"trace=/^({TRACE_CALLS})$"  # strace's regex form: no closing slash
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

_LINE = re.compile(r"^(?:\[pid\s+)?(\d+)\]?\s+(.*)$")
_CALL = re.compile(r"^([a-z0-9_]+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(E[A-Z0-9]+))?.*$")
_UNFINISHED = re.compile(r"^([a-z0-9_]+)\((.*?)\s*<unfinished \.\.\.>$")
_RESUMED = re.compile(r"^<\.\.\. ([a-z0-9_]+) resumed>\s?(.*)$")
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"(?:\.\.\.)?')
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)")
_SIMPLE = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", '"': '"', "\\": "\\"}
_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9]+)")
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_IPV4 = re.compile(r'inet_addr\("([0-9.]+)"\)')
_IPV6 = re.compile(r'inet_pton\(AF_INET6,\s*"([0-9a-fA-F:.]+)"')
_UNIX = re.compile(r'sun_path=(?:@)?"((?:[^"\\]|\\.)*)"')
_START_FOLDER = "/work"


# Package managers written in JavaScript run as `node <their script>`. Naming them by the
# script lets npm read its own .npmrc, while `node evil.js` reading it still counts.
_NODE_TOOLS = {
    "npm-cli.js": "npm",
    "npm": "npm",
    "npx-cli.js": "npx",
    "npx": "npx",
    "yarn.js": "yarn",
    "yarn": "yarn",
    "yarnpkg": "yarn",
    "pnpm.cjs": "pnpm",
    "pnpm": "pnpm",
}


def program_name(path: str, argv: tuple[str, ...]) -> str:
    """The program a process runs. `node /usr/bin/npm` (how Debian starts npm) is npm."""
    name = posixpath.basename(path)
    if name in ("node", "nodejs") and len(argv) > 1:
        return _NODE_TOOLS.get(posixpath.basename(argv[1]), name)
    return name


def _unescape(text: str) -> str:
    def one(m: re.Match[str]) -> str:
        code = m.group(1)
        if code[0] == "x":
            return chr(int(code[1:], 16))
        if code[0].isdigit():
            return chr(int(code, 8))
        return _SIMPLE.get(code, code)

    return _ESCAPE.sub(one, text)


def _strings(args: str) -> list[str]:
    return [_unescape(m.group(1)) for m in _STRING.finditer(args)]


@dataclass(frozen=True)
class Exec:
    pid: int
    path: str
    argv: tuple[str, ...]
    ok: bool
    error: str = ""


@dataclass(frozen=True)
class Open:
    pid: int
    path: str  # absolute when the process's folder is known
    write: bool
    ok: bool
    program: str
    error: str = ""


@dataclass(frozen=True)
class Connect:
    pid: int
    family: str  # AF_INET, AF_INET6, AF_UNIX
    address: str
    port: int | None
    ok: bool
    program: str
    error: str = ""


@dataclass(frozen=True)
class Move:
    pid: int
    source: str
    target: str
    program: str


@dataclass
class Trace:
    execs: list[Exec] = field(default_factory=list)
    opens: list[Open] = field(default_factory=list)
    connects: list[Connect] = field(default_factory=list)
    moves: list[Move] = field(default_factory=list)
    lines: int = 0
    unparsed: int = 0


@dataclass
class _Process:
    folder: str | None = _START_FOLDER
    program: str = "sh"


def parse_trace(
    lines: Iterable[str], *, keep_read: Callable[[str], bool] = lambda path: False
) -> Trace:
    """Calls worth judging: every execve, connect and rename, every open for writing, and
    opens for reading that keep_read wants (the decoy files)."""
    trace = Trace()
    procs: dict[int, _Process] = {}
    pending: dict[int, tuple[str, str]] = {}
    for raw in lines:
        trace.lines += 1
        m = _LINE.match(raw.rstrip("\n"))
        if not m:
            trace.unparsed += 1
            continue
        pid, rest = int(m.group(1)), m.group(2)
        unfinished = _UNFINISHED.match(rest)
        if unfinished:
            pending[pid] = (unfinished.group(1), unfinished.group(2))
            continue
        resumed = _RESUMED.match(rest)
        if resumed:
            name, start = pending.pop(pid, (resumed.group(1), ""))
            tail = resumed.group(2)
            joiner = ", " if start and not tail.startswith(")") else ""
            rest = f"{name}({start}{joiner}{tail}"
        call = _CALL.match(rest)
        if not call:
            if not rest.startswith(("---", "+++")):
                trace.unparsed += 1
            continue
        proc = procs.setdefault(pid, _Process())
        _record(trace, procs, proc, pid, call, keep_read)
    return trace


def _resolve(proc: _Process, path: str, dirfd_relative: bool = False) -> str:
    if path.startswith("/"):
        return posixpath.normpath(path)
    if dirfd_relative or proc.folder is None:
        return path  # relative to a folder lookfirst doesn't know
    return posixpath.normpath(posixpath.join(proc.folder, path))


def _record(
    trace: Trace,
    procs: dict[int, _Process],
    proc: _Process,
    pid: int,
    call: re.Match[str],
    keep_read: Callable[[str], bool],
) -> None:
    name, args, result, error = call.group(1), call.group(2), call.group(3), call.group(4) or ""
    ok = result not in ("?",) and not result.startswith("-")
    strings = _strings(args)
    if name in ("clone", "clone3", "fork", "vfork") and result.isdigit():
        procs[int(result)] = _Process(proc.folder, proc.program)
    elif name == "chdir" and strings and ok:
        proc.folder = _resolve(proc, strings[0])
    elif name == "fchdir" and ok:
        proc.folder = None
    elif name in ("execve", "execveat") and strings:
        path = _resolve(proc, strings[0], name == "execveat" and "AT_FDCWD" not in args)
        bracket = args.find("[")
        argv = tuple(_strings(args[bracket : args.find("]", bracket) + 1])) if bracket >= 0 else ()
        trace.execs.append(Exec(pid, path, argv, ok, error))
        if ok or result == "?":
            proc.program = program_name(path, argv)
    elif name in ("open", "openat", "openat2", "creat") and strings:
        relative_to_fd = name in ("openat", "openat2") and not args.startswith("AT_FDCWD")
        path = _resolve(proc, strings[0], relative_to_fd)
        write = name == "creat" or any(flag in args for flag in WRITE_FLAGS)
        if write or keep_read(path):
            trace.opens.append(Open(pid, path, write, ok, proc.program, error))
    elif name == "connect":
        family = _FAMILY.search(args)
        fam = family.group(1) if family else ""
        if fam == "AF_UNIX":
            unix = _UNIX.search(args)
            address = _unescape(unix.group(1)) if unix else ""
            port = None
        else:
            ip = _IPV4.search(args) or _IPV6.search(args)
            address = ip.group(1) if ip else ""
            port_m = _PORT.search(args)
            port = int(port_m.group(1)) if port_m else None
        if fam:
            # A non-blocking connect reports EINPROGRESS and finishes later: it's under way.
            started = ok or error == "EINPROGRESS"
            trace.connects.append(Connect(pid, fam, address, port, started, proc.program, error))
    elif name in ("rename", "renameat", "renameat2") and len(strings) >= 2 and ok:
        trace.moves.append(
            Move(pid, _resolve(proc, strings[0]), _resolve(proc, strings[1]), proc.program)
        )
