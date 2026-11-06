"""Make untrusted text safe to show.

Anything lookfirst prints from a target (a repo name, a command, a quoted
line from a README) could carry characters that hide or rearrange text, or
terminal escape codes. This module turns them into visible <U+XXXX> marks.
"""

import unicodedata

# Characters that are invisible or change how nearby text is shown, beyond
# the Unicode "control" (Cc) and "format" (Cf) categories, which are always
# made visible: fillers that render as blank space and variation selectors
# that can smuggle hidden data.
_HIDDEN_RANGES = (
    (0x034F, 0x034F),  # combining grapheme joiner
    (0x115F, 0x1160),  # Hangul choseong and jungseong fillers
    (0x17B4, 0x17B5),  # Khmer inherent vowels
    (0x180B, 0x180F),  # Mongolian variation selectors and vowel separator
    (0x3164, 0x3164),  # Hangul filler
    (0xFE00, 0xFE0F),  # variation selectors
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
    (0xE0100, 0xE01EF),  # variation selectors supplement
)

_ELLIPSIS = "…"


def _is_hidden(ch: str) -> bool:
    if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp"):
        return True
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _HIDDEN_RANGES)


def visible(text: str, *, limit: int | None = None, keep_newlines: bool = False) -> str:
    """Return text with hidden and control characters shown as <U+XXXX>.

    Tabs become four spaces. Newlines are kept only if keep_newlines is set.
    If limit is given, the result is cut to at most that many characters,
    never in the middle of a <U+XXXX> mark, and ends with an ellipsis.
    """
    pieces: list[str] = []
    length = 0
    for ch in text:
        if ch == "\n" and keep_newlines:
            piece = ch
        elif ch == "\t":
            piece = "    "
        elif _is_hidden(ch):
            piece = f"<U+{ord(ch):04X}>"
        else:
            piece = ch
        pieces.append(piece)
        length += len(piece)
        if limit is not None and length > limit:
            # Too long: drop whole pieces until the ellipsis fits.
            while pieces and length > limit - 1:
                length -= len(pieces.pop())
            return "".join(pieces) + _ELLIPSIS
    return "".join(pieces)


def one_line(text: str, limit: int | None = None) -> str:
    """Like visible(), with newlines shown as marks so the text stays on one line."""
    return visible(text, limit=limit, keep_newlines=False)
