"""How much of a README is copied from another.

Both READMEs become sets of 5-word runs ("shingles"). Two numbers come out:
- Jaccard similarity: shared runs over all runs (SPEC section 4: 0.6 or more = copied).
- Containment: the share of the original's runs found in the target. Impersonators often
  copy the whole README and add a download section, which lowers Jaccard but not this.

Comparing two READMEs exactly is cheap, so this doesn't need MinHash, which only
estimates the same Jaccard number when comparing thousands at once.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

SHINGLE_WORDS = 5
_BADGE = re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)|!\[[^\]]*\]\([^)]*\)")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_TAG = re.compile(r"<[^>]+>")
_URL = re.compile(r"https?://\S+")
_WORD = re.compile(r"[a-z0-9]+")


def readme_words(text: str) -> list[str]:
    """The README's words, without badges, link targets, HTML tags or URLs."""
    text = _BADGE.sub(" ", text)
    text = _LINK.sub(r" \1 ", text)
    text = _TAG.sub(" ", text)
    text = _URL.sub(" ", text)
    return _WORD.findall(text.lower())


def _hash(run: str) -> int:
    return int.from_bytes(hashlib.blake2b(run.encode(), digest_size=8).digest(), "big")


def shingles(text: str, k: int = SHINGLE_WORDS) -> set[int]:
    w = readme_words(text)
    return {_hash(" ".join(w[i : i + k])) for i in range(len(w) - k + 1)}


@dataclass(frozen=True)
class Similarity:
    jaccard: float
    containment: float  # share of the original's text found in the target
    shared: int

    @property
    def copied(self) -> bool:
        return self.jaccard >= 0.6 or (self.containment >= 0.8 and self.shared >= 40)

    @property
    def percent(self) -> int:
        return round(100 * max(self.jaccard, self.containment))


def similarity(target_text: str, original_text: str) -> Similarity:
    target, original = shingles(target_text), shingles(original_text)
    if not target or not original:
        return Similarity(0.0, 0.0, 0)
    shared = len(target & original)
    return Similarity(shared / len(target | original), shared / len(original), shared)
