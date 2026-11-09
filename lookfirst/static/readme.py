"""Find the install commands in a README: shell code under install, quick start, usage or
setup headings (including their subsections), plus the introduction before the first
section."""

from __future__ import annotations

import re
from dataclasses import dataclass

from markdown_it import MarkdownIt

_MD = MarkdownIt("commonmark")
_SECTION = re.compile(
    r"install|quick ?start|getting started|get started|usage|set ?up|build|running|run it|try it"
    r"|bootstrap",
    re.IGNORECASE,
)
_SHELL_FENCES = {
    "",
    "sh",
    "bash",
    "shell",
    "zsh",
    "console",
    "terminal",
    "shell-session",
    "shellsession",
    "fish",
}
_TRANSCRIPTS = {"console", "terminal", "shell-session", "shellsession"}
_PROMPT = re.compile(r"^\s*(?:\$|%|❯)\s+")  # noqa: RUF001 - a common prompt character
_COMMANDS = re.compile(
    r"^\s*(?:sudo\s+)?(?:curl|wget|bash|sh|zsh|npm|npx|pnpm|yarn|bun|bunx|pip|pip3|pipx|uv|uvx|python|python3|"
    r"brew|apt|apt-get|yum|dnf|git|make|just|cargo|go|docker|chmod|cd|export|source|eval|deno|node|gem|"
    r"conda|poetry|rustup|nix|xattr|open|ln|cp|mv|tar|unzip|mkdir)\b"
)


@dataclass(frozen=True)
class CodeBlock:
    text: str
    line: int  # 1-based line of the block's first line in the README


def _shell_lines(content: str, info: str) -> str:
    lines = content.splitlines()
    if info in _TRANSCRIPTS or any(_PROMPT.match(x) for x in lines):
        # A transcript: only lines with a prompt are commands; the rest is output.
        return "\n".join(_PROMPT.sub("", x) if _PROMPT.match(x) else "" for x in lines)
    if info == "" and not any(_COMMANDS.match(x) for x in lines):
        return ""  # an unlabeled block that doesn't look like commands
    return content


def install_blocks(text: str) -> list[CodeBlock]:
    tokens = _MD.parse(text)
    blocks: list[CodeBlock] = []
    stack: list[tuple[int, str]] = []  # the headings above the current position
    pending_level = 0
    in_heading = False
    for tok in tokens:
        if tok.type == "heading_open":
            in_heading = True
            pending_level = int(tok.tag[1:]) if tok.tag[1:].isdigit() else 2
            continue
        if in_heading and tok.type == "inline":
            in_heading = False
            while stack and stack[-1][0] >= pending_level:
                stack.pop()
            stack.append((pending_level, tok.content))
            continue
        sections = [h for level, h in stack if level >= 2]
        relevant = not sections or any(_SECTION.search(h) for _, h in stack)
        if not relevant:
            continue
        if tok.type == "fence" and tok.map:
            info = (tok.info or "").strip().split(" ")[0].lower()
            if info not in _SHELL_FENCES:
                continue
            code = _shell_lines(tok.content, info)
            if code.strip():
                blocks.append(CodeBlock(code, tok.map[0] + 2))
        elif tok.type == "inline" and tok.map:
            for child in tok.children or []:
                content = child.content
                if child.type == "code_inline" and _COMMANDS.match(content) and (" " in content):
                    blocks.append(CodeBlock(content, tok.map[0] + 1))
    return blocks
