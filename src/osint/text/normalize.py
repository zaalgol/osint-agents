"""Text normalization with an index map back to the original string.

Matching quotes and names must tolerate differences that don't change meaning (Unicode
forms, whitespace, typographic quotes, Arabic/Hebrew diacritics, case), while always
reporting offsets in the *original* text.
"""

from __future__ import annotations

import re
import unicodedata

# Code points as integers on purpose: invisible characters must never appear literally in source.
_ZERO_WIDTH = {chr(c) for c in (
    0x200B, 0x200C, 0x200D,  # zero-width space / non-joiner / joiner
    0x200E, 0x200F,          # left-to-right / right-to-left marks
    0x2060, 0xFEFF, 0x00AD,  # word joiner, BOM, soft hyphen
    0x0640,                  # Arabic tatweel
)}
_PUNCT_MAP = {
    # All quotation marks fold to one: LLMs writing JSON swap " for ' to avoid escaping,
    # and the swap doesn't change what was said.
    **dict.fromkeys((0x2018, 0x2019, 0x201A, 0x201B, 0x2032), "'"),
    **dict.fromkeys((0x22, 0x201C, 0x201D, 0x201E, 0x201F, 0x2033, 0x00AB, 0x00BB), "'"),
    **dict.fromkeys((0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212), "-"),  # dashes
    # Arabic letter-variant folding: alef forms -> alef, alef maqsura -> yeh, ta marbuta -> heh
    **dict.fromkeys((0x0623, 0x0625, 0x0622, 0x0671), chr(0x0627)),
    0x0649: chr(0x064A),
    0x0629: chr(0x0647),
    # Persian/Urdu keheh -> kaf, Farsi yeh -> yeh
    0x06A9: chr(0x0643),
    0x06CC: chr(0x064A),
}


def _fold_char(c: str) -> str:
    if c in _ZERO_WIDTH:
        return ""
    out = []
    for d in unicodedata.normalize("NFKD", c):
        if unicodedata.category(d) == "Mn":  # combining marks: accents, harakat, niqqud
            continue
        out.append(d)
    return "".join(out).translate(_PUNCT_MAP).casefold()


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Return (normalized, idx) where normalized[k] came from text[idx[k]]."""
    out: list[str] = []
    idx: list[int] = []
    prev_space = True  # also trims leading whitespace
    for i, c in enumerate(text):
        if c.isspace():
            if not prev_space:
                out.append(" ")
                idx.append(i)
                prev_space = True
            continue
        folded = _fold_char(c)
        for f in folded:
            if f.isspace():
                if prev_space:
                    continue
                prev_space = True
            else:
                prev_space = False
            out.append(f)
            idx.append(i)
    if out and out[-1] == " ":
        out.pop()
        idx.pop()
    return "".join(out), idx


def normalize(text: str) -> str:
    return normalize_with_map(text)[0]


_NON_WORD = re.compile(r"[^\w]+", re.UNICODE)


def name_key(name: str) -> str:
    """Comparison key for names: folded, punctuation removed, whitespace collapsed."""
    return " ".join(_NON_WORD.sub(" ", normalize(name)).split())
