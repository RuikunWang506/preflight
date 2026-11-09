import pytest

from lookfirst.core.textsafe import one_line, visible


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain text", "plain text"),
        ("café 中文 🙂", "café 中文 🙂"),
        ("zero\u200bwidth", "zero<U+200B>width"),
        ("bidi \u202eevil\u202c", "bidi <U+202E>evil<U+202C>"),
        ("isolate\u2066x\u2069", "isolate<U+2066>x<U+2069>"),
        ("tag\U000e0041\U000e0042", "tag<U+E0041><U+E0042>"),
        ("bom\ufeff", "bom<U+FEFF>"),
        ("filler\u3164", "filler<U+3164>"),
        ("variation\ufe0f", "variation<U+FE0F>"),
        ("esc \x1b[31mred", "esc <U+001B>[31mred"),
        ("bell\x07", "bell<U+0007>"),
        ("a\tb", "a    b"),
    ],
)
def test_hidden_and_control_characters_become_visible(text: str, expected: str) -> None:
    assert visible(text) == expected


def test_newlines_are_marks_unless_kept() -> None:
    assert one_line("a\nb") == "a<U+000A>b"
    assert visible("a\nb", keep_newlines=True) == "a\nb"


def test_limit_keeps_text_that_fits() -> None:
    assert visible("abc", limit=3) == "abc"


def test_limit_cuts_with_an_ellipsis() -> None:
    assert visible("abcdef", limit=4) == "abc…"


def test_limit_never_splits_a_mark() -> None:
    out = visible("ab\u200bcd", limit=6)
    assert out == "ab…"
    assert len(out) <= 6
