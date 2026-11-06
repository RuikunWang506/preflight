"""Read shell code into a flat list of commands, using tree-sitter-bash. Nothing is run.

Each command keeps what the rules need: its words (with simple variables and quoting
resolved where that's possible without running anything), its redirects, any
here-document, which pipeline it's in and where, and whether it sits inside a
`$(...)` or `<(...)` of another command. Lines the parser can't read are reported,
never silently skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter_bash
from tree_sitter import Language, Node, Parser

_PARSER = Parser(Language(tree_sitter_bash.language()))
_ANSI_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|[0-7]{1,3}|.)")
_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "a": "\a",
    "b": "\b",
    "e": "\x1b",
    "\\": "\\",
    "'": "'",
    '"': '"',
}
DYNAMIC = "\x00"  # marks a part of a word that's only known when it runs


@dataclass
class Redirect:
    op: str  # ">", ">>", "<", "&>", "2>" ...
    target: str
    line: int


@dataclass
class Command:
    index: int
    argv: list[str]
    raw: str
    line: int  # 1-based, relative to the parsed text
    redirects: list[Redirect] = field(default_factory=list)
    heredoc: str | None = None
    herestring: str | None = None
    pipeline: int | None = None
    position: int = 0  # place in its pipeline, from 0
    parent: int | None = None  # the command whose $(...) or <(...) holds this one
    subst: str | None = None  # "command", "process_in" or "process_out"
    parent_arg: int | None = None  # which word of the parent holds the substitution
    dynamic: bool = False  # some words are only known when it runs
    obfuscated: bool = False  # the command name was spelled with escape codes

    @property
    def name(self) -> str:
        return self.argv[0].rsplit("/", 1)[-1] if self.argv else ""


@dataclass
class ParsedScript:
    commands: list[Command]
    unreadable: list[tuple[int, int]]  # line ranges (1-based, inclusive)
    variables: dict[str, str]

    def children(self, index: int) -> list[Command]:
        return [c for c in self.commands if c.parent == index]

    def pipeline(self, pid: int) -> list[Command]:
        return [c for c in self.commands if c.pipeline == pid]


def decode_ansi_c(body: str) -> str:
    def repl(m: re.Match[str]) -> str:
        esc = m.group(1)
        if esc[0] == "x":
            return chr(int(esc[1:], 16))
        if esc[0] == "u":
            return chr(int(esc[1:], 16))
        if esc[0] in "01234567":
            return chr(int(esc, 8))
        return _SIMPLE_ESCAPES.get(esc, esc)

    return _ANSI_ESCAPE.sub(repl, body)


def _unescape_word(text: str) -> str:
    return re.sub(r"\\(.)", r"\1", text)


class _Walker:
    def __init__(self, src: bytes) -> None:
        self.src = src
        self.commands: list[Command] = []
        self.variables: dict[str, str] = {}
        self._pipelines = 0

    def text(self, node: Node) -> str:
        return self.src[node.start_byte : node.end_byte].decode("utf-8", "replace")

    # --- words ---------------------------------------------------------------

    def word(self, node: Node) -> tuple[str, bool, bool, list[tuple[str, Node]]]:
        """Return (text, dynamic, obfuscated, substitutions) for a word-like node."""
        t = node.type
        if t == "command_name":
            kids = node.named_children
            if kids:
                return self.word(kids[0])
            return self.text(node), False, False, []
        if t == "word":
            raw = self.text(node)
            # One leading backslash (\rm, \.) is the usual way to skip aliases, and "\ " is an
            # escaped space in a path. Backslashes before letters inside a name (c\u\r\l) only
            # serve to hide what it is.
            return _unescape_word(raw), False, bool(re.search(r"\\[A-Za-z0-9]", raw[1:])), []
        if t == "raw_string":
            return self.text(node)[1:-1], False, False, []
        if t == "ansi_c_string":
            body = self.text(node)[2:-1]
            return decode_ansi_c(body), False, bool(re.search(r"\\(x|u|[0-7])", body)), []
        if t == "number":
            return self.text(node), False, False, []
        if t in ("simple_expansion", "expansion"):
            return self._expansion(node)
        if t == "command_substitution":
            return f"$({DYNAMIC})", True, False, [("command", node)]
        if t == "process_substitution":
            kind = "process_in" if self.text(node).startswith("<") else "process_out"
            return f"<({DYNAMIC})", True, False, [(kind, node)]
        if t in ("string", "concatenation", "translated_string"):
            parts: list[str] = []
            dynamic = obfuscated = False
            substs: list[tuple[str, Node]] = []
            for child in node.named_children:
                if child.type == "string_content":
                    parts.append(self.text(child))
                    continue
                value, dyn, obf, sub = self.word(child)
                parts.append(value)
                dynamic |= dyn
                obfuscated |= obf
                substs += sub
            if t == "concatenation" and not node.named_children:
                parts.append(self.text(node))
            return "".join(parts), dynamic, obfuscated, substs
        # arithmetic, brace expressions and anything else: keep the source text
        substs = [(k, n) for child in node.named_children for k, n in self.word(child)[3]]
        return self.text(node), True, False, substs

    def _expansion(self, node: Node) -> tuple[str, bool, bool, list[tuple[str, Node]]]:
        raw = self.text(node)
        m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", raw)
        if m:
            name = m.group(1)
            if name == "HOME":
                return "~", False, False, []
            if name in self.variables:
                return self.variables[name], False, False, []
            return f"${{{name}}}", True, False, []
        substs = [(k, n) for child in node.named_children for k, n in self.word(child)[3]]
        return raw, True, False, substs

    # --- statements ----------------------------------------------------------

    def visit(self, node: Node, ctx: dict) -> None:
        t = node.type
        if t == "pipeline":
            self._pipelines += 1
            pid = self._pipelines
            for position, child in enumerate(node.named_children):
                self.visit(child, {**ctx, "pipeline": pid, "position": position})
            return
        if t == "redirected_statement":
            redirects, heredoc, herestring, extra = self._redirects(node, ctx)
            body = node.child_by_field_name("body")
            if body is not None:
                self.visit(
                    body,
                    {**ctx, "redirects": redirects, "heredoc": heredoc, "herestring": herestring},
                )
            for child in extra:  # e.g. the "| bash" in "cat <<EOF | bash"
                self.visit(child, {**ctx, "position": ctx.get("position", 0) + 1})
            return
        if t == "command":
            self._command(node, ctx)
            return
        if t == "variable_assignment":
            self._assignment(node, ctx)
            return
        if t in ("command_substitution", "process_substitution"):
            kind = "command" if t == "command_substitution" else "process_in"
            for child in node.named_children:
                self.visit(child, {**ctx, "subst": kind, "pipeline": None, "position": 0})
            return
        clean = {k: v for k, v in ctx.items() if k not in ("redirects", "heredoc", "herestring")}
        for child in node.named_children:
            self.visit(child, clean)

    def _assignment(self, node: Node, ctx: dict) -> None:
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None:
            return
        if value_node is None:
            self.variables[self.text(name_node)] = ""
            return
        value, dynamic, _, substs = self.word(value_node)
        if not dynamic:
            self.variables[self.text(name_node)] = value
        for kind, sub in substs:
            for child in sub.named_children:
                self.visit(child, {**ctx, "subst": kind, "pipeline": None, "position": 0})

    def _redirects(
        self, node: Node, ctx: dict
    ) -> tuple[list[Redirect], str | None, str | None, list[Node]]:
        redirects: list[Redirect] = []
        heredoc = herestring = None
        extra: list[Node] = []
        for r in node.children_by_field_name("redirect"):
            line = r.start_point[0] + 1
            if r.type == "file_redirect":
                dest = r.child_by_field_name("destination")
                if dest is None:
                    continue
                op = self.src[r.start_byte : dest.start_byte].decode("utf-8", "replace").strip()
                target, _, _, _ = self.word(dest)
                redirects.append(Redirect(op=op, target=target, line=line))
            elif r.type == "heredoc_redirect":
                for child in r.named_children:
                    if child.type == "heredoc_body":
                        heredoc = self.text(child)
                    elif child.type in ("pipeline", "command", "list", "redirected_statement"):
                        extra.append(child)
            elif r.type == "herestring_redirect":
                for child in r.named_children:
                    value, _, _, substs = self.word(child)
                    herestring = value
                    for kind, sub in substs:
                        for grandchild in sub.named_children:
                            self.visit(
                                grandchild, {**ctx, "subst": kind, "pipeline": None, "position": 0}
                            )
        return redirects, heredoc, herestring, extra

    def _command(self, node: Node, ctx: dict) -> None:
        name_node = node.child_by_field_name("name")
        if name_node is None:  # only assignments, like "FOO=1"
            for child in node.named_children:
                if child.type == "variable_assignment":
                    self._assignment(child, ctx)
            return
        words = [name_node, *node.children_by_field_name("argument")]
        index = len(self.commands)
        cmd = Command(
            index=index,
            argv=[],
            raw=self.text(node),
            line=node.start_point[0] + 1,
            redirects=list(ctx.get("redirects") or []),
            heredoc=ctx.get("heredoc"),
            herestring=ctx.get("herestring"),
            pipeline=ctx.get("pipeline"),
            position=ctx.get("position", 0),
            parent=ctx.get("parent"),
            subst=ctx.get("subst"),
            parent_arg=ctx.get("parent_arg"),
        )
        self.commands.append(cmd)
        pending: list[tuple[int, str, Node]] = []
        for i, w in enumerate(words):
            value, dynamic, obfuscated, substs = self.word(w)
            cmd.argv.append(value)
            cmd.dynamic |= dynamic
            if i == 0 and obfuscated:
                cmd.obfuscated = True
            pending += [(i, kind, sub) for kind, sub in substs]
        for i, kind, sub in pending:
            for child in sub.named_children:
                self.visit(child, {"parent": index, "subst": kind, "parent_arg": i})


def _error_ranges(node: Node) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            ranges.append((n.start_point[0] + 1, n.end_point[0] + 1))
            continue
        if n.has_error:
            stack.extend(n.children)
    ranges.sort()
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def parse_shell(text: str) -> ParsedScript:
    src = text.encode("utf-8", "replace")
    tree = _PARSER.parse(src)
    walker = _Walker(src)
    walker.visit(tree.root_node, {})
    return ParsedScript(
        commands=walker.commands,
        unreadable=_error_ranges(tree.root_node),
        variables=walker.variables,
    )
