"""Prompt injection aimed at AI agents (SPEC section 6, second half).

lookfirst quotes what it finds and never acts on it. The patterns look for text that is
*addressed to* an AI agent and asks it to act, text that tries to override an agent's
instructions or keep things from the user, and instructions hidden where people won't
see them. Ordinary instructions in AGENTS.md or CLAUDE.md ("run npm test") are expected
and aren't flagged.
"""

from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path

from lookfirst.static.files import read_text, walk
from lookfirst.static.model import Collector

_TEXT_SUFFIXES = frozenset({".md", ".mdx", ".markdown", ".rst", ".txt", ".mdc", ".adoc"})
_CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".sh",
        ".bash",
        ".zsh",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".swift",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".php",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".lua",
        ".pl",
    }
)
_PLAIN_TEXT_NAMES = frozenset(
    {"README", "CONTRIBUTING", "INSTALL", ".cursorrules", ".windsurfrules", ".clinerules"}
)
_MAX_BYTES = 512 * 1024

# Generic phrases for AI agents, and product names. Names only count when the text speaks
# to them directly ("Note for Copilot:", "Dear Claude"), since READMEs mention them a lot.
_AI = (
    r"(?:AI|A\.I\.)\s+(?:coding\s+)?(?:agents?|assistants?|models?|tools?|bots?)|coding\s+(?:agents?|assistants?)"
    r"|LLMs?|large\s+language\s+models?|language\s+models?|chat\s?bots?"
)
_NAMES = r"Claude(?:\s+Code)?|ChatGPT|Copilot|Cursor|Gemini|Codex|Windsurf|Cline|Devin|Aider"
_ADDRESSED = re.compile(
    rf"\b(?:attention|note|message|instructions?|info|hint|important|reminder)\s*(?:for|to)\s+(?:all\s+|any\s+|the\s+)?(?:{_AI}|{_NAMES}|agents?|assistants?|AIs?)\b"
    rf"|\bif\s+you\s+are\s+(?:an?\s+)?(?:{_AI}|{_NAMES}|AI|assistant|agent|bot|LLM)\b"
    rf"|\b(?:dear|hey|hi|hello|attention)\s+(?:{_AI}|{_NAMES}|AI)\b"
    rf"|(?:^|\n)\s*(?:[>*_-]\s*)*(?:{_AI}|{_NAMES})\s*[:,]"
    rf"|\b(?:{_AI})\s+(?:should|must|need\s+to|are\s+required\s+to|reading\s+this|processing\s+this)\b",
    re.IGNORECASE,
)
# Text that tries to override an AI agent's instructions. Enough on its own.
_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your\s+|the\s+)?(?:previous|prior|above|earlier|system|original)\s+(?:instructions?|rules|guidelines|prompts?|directions)\b"
    r"|\bkeep\s+(?:this|it)\s+(?:secret|hidden)\s+from\s+(?:the\s+)?user\b"
    r"|\bnew\s+(?:system\s+)?instructions\s*:"
    r"|\b(?:this|the)\s+(?:repo|repository|project|package|code|tool)\s+(?:is|has\s+been)\s+(?:verified|certified|approved|confirmed)\s+(?:as\s+|to\s+be\s+)?safe\b"
    r"|\b(?:do\s+not|don'?t)\s+(?:report|flag|mention)\s+(?:any\s+)?(?:issues|problems|warnings|findings)\b",
    re.IGNORECASE,
)
# Keeping things from the user. Technical writing says this too ("fails without notifying
# the user"), so it only counts with an AI being addressed or asked to run something.
_SECRECY = re.compile(
    r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|alert|notify|warn|ask)\s+(?:the\s+)?user\b"
    r"|\b(?:do\s+not|don'?t|never)\s+mention\s+(?:this|it|these)\s+to\s+(?:the\s+)?user\b"
    r"|\bwithout\s+(?:asking|telling|informing|notifying|warning|confirming\s+with)\s+(?:the\s+)?user\b",
    re.IGNORECASE,
)
_COMMAND = re.compile(
    r"\b(?:run|execute|exec|paste|type|launch|start|install)\b[^.\n]{0,80}\b(?:command|script|curl|wget|bash|sh|terminal|shell|npx|following)\b"
    r"|\bcurl\s[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"
    r"|\b(?:download|fetch)\b[^.\n]{0,60}\b(?:run|execute)\b",
    re.IGNORECASE,
)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_ALT_MD = re.compile(r"!\[([^\]]{12,})\]\(")
_ALT_HTML = re.compile(r"<img\b[^>]*\balt\s*=\s*([\"'])(.{12,}?)\1", re.IGNORECASE | re.DOTALL)
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=,])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
_TAGS = re.compile(r"[\U000E0000-\U000E007F]+")
_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
# Zero-width characters are normal in Persian, Arabic, Thai and emoji, so they only count
# between plain ASCII text, where they serve to hide or split words. Fillers that
# draw as blank space and a byte-order mark mid-file always count.
_INVISIBLE = re.compile(
    r"(?<=[\x20-\x7e])[\u200b\u200c\u200d\u2060-\u2064](?=[\x20-\x7e])"
    r"|[\u180e\u115f\u1160\u3164\uffa0]|(?<!^)\ufeff"
)
_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|specs?|fixtures|testdata)/|(?:^|/)test_[^/]*$")
_COMMENT_LINE = re.compile(r"^\s*(?:#|//|/\*|\*|<!--|--|;)\s?(.*)$")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _directive(text: str, *, lenient: bool = False) -> re.Match[str] | None:
    """The match that makes this text an instruction aimed at AI agents, if any. In agent
    instruction files (lenient), asking the agent to run things is normal."""
    strong = _OVERRIDE.search(text)
    secrecy = _SECRECY.search(text)
    if lenient:
        return strong or secrecy
    addressed = _ADDRESSED.search(text)
    command = _COMMAND.search(text)
    if strong:
        return strong
    if secrecy and (addressed or command):
        return addressed or secrecy
    if addressed and command:
        return addressed
    return None


def _instruction_like(text: str) -> bool:
    return bool(
        _ADDRESSED.search(text)
        or (_OVERRIDE.search(text) or _SECRECY.search(text))
        or _COMMAND.search(text)
    )


def _aimed_at_agents(text: str) -> bool:
    """For places people leave notes for each other (HTML comments, image descriptions):
    only text addressed to an AI, or trying to deceive one, counts."""
    return bool(_ADDRESSED.search(text) or (_OVERRIDE.search(text) or _SECRECY.search(text)))


def _hidden(text: str, rel: str, out: Collector) -> None:
    for m in _HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if len(body) >= 12 and _aimed_at_agents(body):
            out.add(
                "injection.hidden_instructions",
                path=rel,
                line=_line(text, m.start()),
                excerpt=body,
                data={"where": "an HTML comment, which isn't shown on the page"},
            )
    for pattern, group in ((_ALT_MD, 1), (_ALT_HTML, 2)):
        for m in pattern.finditer(text):
            alt = m.group(group)
            if _aimed_at_agents(alt):
                out.add(
                    "injection.hidden_instructions",
                    path=rel,
                    line=_line(text, m.start()),
                    excerpt=alt,
                    data={"where": "an image description"},
                )
    for m in _BASE64.finditer(text):
        before = text[max(0, m.start() - 8) : m.start()].lower()
        if "base64" in before:
            continue  # a data: URI, such as a badge image
        try:
            decoded = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            plain = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in plain) / max(len(plain), 1)
        if printable > 0.9 and _instruction_like(plain):
            out.add(
                "injection.hidden_instructions",
                path=rel,
                line=_line(text, m.start()),
                excerpt="decodes to: " + plain,
                data={"where": "a base64 blob"},
            )
    for m in _TAGS.finditer(text):
        run = m.group(0)
        flag = text[max(0, m.start() - 1) : m.start()] == "\U0001f3f4" and run.endswith(
            "\U000e007f"
        )
        if flag and len(run) <= 8:
            continue  # a regional flag emoji, such as England's, is built from tag characters
        hidden = "".join(chr(ord(ch) - 0xE0000) for ch in run if 0xE0020 <= ord(ch) <= 0xE007E)
        if hidden.strip():
            out.add(
                "injection.hidden_instructions",
                path=rel,
                line=_line(text, m.start()),
                excerpt="hidden text: " + hidden,
                data={"where": "invisible Unicode tag characters"},
            )


def _blank(m: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", m.group(0))  # keep line numbers


def _visible(text: str, rel: str, out: Collector, *, lenient: bool) -> None:
    # HTML comments and image descriptions are checked as hidden text, not here.
    text = _ALT_HTML.sub(_blank, _ALT_MD.sub(_blank, _HTML_COMMENT.sub(_blank, text)))
    for m in re.finditer(r"(?:[^\n]+\n?)+", text):  # paragraphs
        para = m.group(0)
        hit = _directive(para, lenient=lenient)
        if hit:
            start = m.start() + hit.start()
            out.add(
                "injection.agent_directed", path=rel, line=_line(text, start), excerpt=para.strip()
            )


def _characters(
    text: str, rel: str, out: Collector, *, code: bool, test_file: bool = False
) -> None:
    bidi = list(_BIDI.finditer(text))
    if bidi:
        # In tests, direction changes usually test right-to-left text: still shown, as medium.
        rule = (
            "injection.trojan_source"
            if code and not test_file
            else "injection.invisible_characters"
        )
        first = bidi[0]
        line_start = text.rfind("\n", 0, first.start()) + 1
        line_end = text.find("\n", first.start())
        out.add(
            rule,
            path=rel,
            line=_line(text, first.start()),
            excerpt=text[line_start : line_end if line_end >= 0 else None],
            data={"what": f"{len(bidi)} direction-changing characters"},
        )
    # Test files often hold such characters on purpose; direction changes still count there.
    hidden = [] if test_file else list(_INVISIBLE.finditer(text))
    # One stray character in prose is usually a copy-paste accident (a name in AUTHORS.txt);
    # hiding text takes several. In code, one is enough.
    if len(hidden) >= (1 if code else 3):
        first = hidden[0]
        line_start = text.rfind("\n", 0, first.start()) + 1
        line_end = text.find("\n", first.start())
        out.add(
            "injection.invisible_characters",
            path=rel,
            line=_line(text, first.start()),
            excerpt=text[line_start : line_end if line_end >= 0 else None],
            data={"what": f"{len(hidden)} invisible characters"},
        )


def _comments(text: str, rel: str, out: Collector) -> None:
    block: list[tuple[int, str]] = []

    def flush() -> None:
        if block:
            joined = "\n".join(t for _, t in block)
            if _directive(joined):
                out.add("injection.agent_directed", path=rel, line=block[0][0], excerpt=joined)
            block.clear()

    for number, line in enumerate(text.splitlines(), start=1):
        m = _COMMENT_LINE.match(line)
        if m:
            block.append((number, m.group(1)))
        else:
            flush()
    flush()


def check_injection(root: Path, instruction_files: list[str], out: Collector) -> None:
    lenient = set(instruction_files)
    text_files = code_files = 0
    for rel in walk(root, max_files=20_000):
        name = rel.rsplit("/", 1)[-1]
        suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        is_text = suffix in _TEXT_SUFFIXES or name in _PLAIN_TEXT_NAMES or rel in lenient
        is_code = suffix in _CODE_SUFFIXES
        if is_text and text_files < 500:
            text = read_text(root, rel, max_bytes=_MAX_BYTES)
            if text is None:
                continue
            text_files += 1
            _hidden(text, rel, out)
            _visible(text, rel, out, lenient=rel in lenient)
            _characters(text, rel, out, code=False)
        elif is_code and code_files < 2000:
            text = read_text(root, rel, max_bytes=_MAX_BYTES)
            if text is None:
                continue
            code_files += 1
            _characters(text, rel, out, code=True, test_file=bool(_TEST_PATH.search(rel)))
            _comments(text, rel, out)
