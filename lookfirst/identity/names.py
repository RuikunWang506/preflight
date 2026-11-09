"""How alike two GitHub names are: near-misses, look-alike letters, and the words
impersonators add (-pro, -free, -official...). GitHub names are plain ASCII, so the
look-alike letters that matter are ASCII too."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

_SEPARATORS = re.compile(r"[-_.]+")
# Shapes that look alike in most fonts: rn/m, vv/w, 0/o, and l/I/1/i/|.
_DIGRAPHS = (("rn", "m"), ("vv", "w"))
_LETTERS = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l"})
# Words impersonators add to a real project's name. Years are added too ("tool-2026").
ADDED_WORDS = frozenset(
    {
        "pro",
        "free",
        "official",
        "download",
        "downloads",
        "crack",
        "cracked",
        "fixed",
        "premium",
        "unlocked",
        "latest",
        "full",
        "setup",
        "installer",
        "patched",
        "keygen",
        "hack",
        "hacked",
        "cheat",
        "cheats",
        "activated",
        "portable",
        "updated",
        "working",
    }
)
_YEAR = re.compile(r"^(?:19|20)\d\d$")

MatchKind = Literal["same_name", "lookalike_name", "added_word", "near_name", "lookalike_owner"]


@dataclass(frozen=True)
class NameMatch:
    kind: MatchKind
    detail: str  # plain English, made only from GitHub names (letters, digits, - _ .)


def fold(name: str) -> str:
    """Lowercase, with look-alike letters folded to one form."""
    text = name.lower()
    for pair, single in _DIGRAPHS:
        text = text.replace(pair, single)
    return text.translate(_LETTERS)


def squash(name: str) -> str:
    """fold() without separators: "Yt_D1p" and "yt-dlp" both become "ytdlp"."""
    return _SEPARATORS.sub("", fold(name))


def words(name: str) -> list[str]:
    """Split a name into words at separators and lower-to-upper case changes."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    return [w for w in re.split(r"[-_.\s]+", spaced.lower()) if w]


def distance(a: str, b: str, limit: int = 2) -> int:
    """Edit distance with swaps of neighbors (optimal string alignment). Returns limit + 1
    as soon as it's clear the distance is larger than limit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous2: list[int] = []
    previous = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        current = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                current[j] = min(current[j], previous2[j - 2] + 1)
        if min(current) > limit:
            return limit + 1
        previous2, previous = previous, current
    return min(previous[-1], limit + 1)


def without_added_words(name: str) -> tuple[str, list[str]]:
    """The name without impersonators' added words, squashed, and the words removed."""
    kept, removed = [], []
    for word in words(name):
        if word in ADDED_WORDS or _YEAR.match(word):
            removed.append(word)
        else:
            kept.append(word)
    return squash("".join(kept)), removed


def compare(
    target_owner: str, target_repo: str, orig_owner: str, orig_repo: str
) -> list[NameMatch]:
    """How the target's name resembles the original's. Empty if it doesn't."""
    matches: list[NameMatch] = []
    original = f"{orig_owner}/{orig_repo}"
    t, o = target_repo.lower(), orig_repo.lower()
    if t == o:
        matches.append(NameMatch("same_name", f"the same name as {original}, under another owner"))
    elif squash(target_repo) == squash(orig_repo):
        how = "look-alike letters" if fold(t) != t or fold(o) != o else "different punctuation"
        matches.append(NameMatch("lookalike_name", f"{original}'s name spelled with {how}"))
    else:
        stripped, removed = without_added_words(target_repo)
        if removed and stripped == squash(orig_repo):
            added = ", ".join(f'"{w}"' for w in removed)
            matches.append(NameMatch("added_word", f"{original}'s name with {added} added"))
        elif len(o) >= 6 and distance(squash(t), squash(o)) <= 2:
            matches.append(NameMatch("near_name", f"one or two letters away from {original}"))
    to, oo = target_owner.lower(), orig_owner.lower()
    if to != oo:
        st, so = squash(to), squash(oo)
        lookalike = st == so or (len(so) >= 5 and distance(st, so) <= 2)
        if not lookalike and len(so) >= 4 and (st.startswith(so) or st.endswith(so)):
            lookalike = True  # "ollama-dev" for "ollama"
        if lookalike:
            matches.append(
                NameMatch("lookalike_owner", f"an owner name that looks like {orig_owner}")
            )
    return matches
