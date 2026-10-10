"""Quote verification: every quote must really occur in the document.

Allowed: exact match, or a match after meaning-preserving normalization (see
osint.text.normalize), or an elided quote ("A ... B") whose parts occur in order
close together. Fuzzy matching is deliberately NOT allowed for ordinary text, because
an LLM paraphrase is not a citation. (OCR/transcripts get a fuzzy mode later.)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from osint.text.normalize import normalize, normalize_with_map

_ELLIPSIS = re.compile(r"\s*(?:\.\.\.+|…|\[\.\.\.\]|\(\.\.\.\))\s*")
_EDGE = " \t\n\"'“”‘’«».,;:!?…-–—()[]"
MAX_ELISION_GAP = 600  # chars between elided parts


@dataclass(frozen=True)
class QuoteMatch:
    start: int
    end: int
    method: str  # exact | normalized | elided

    def text(self, doc: str) -> str:
        return doc[self.start:self.end]


class QuoteIndex:
    """Normalized view of one document, reused for all quotes from it."""

    def __init__(self, text: str):
        self.text = text
        self.norm, self.idx = normalize_with_map(text)

    def _span(self, nstart: int, nend: int) -> tuple[int, int]:
        return self.idx[nstart], self.idx[nend - 1] + 1

    def _find_norm(self, nq: str, from_n: int = 0) -> int:
        return self.norm.find(nq, from_n) if nq else -1

    def find(self, quote: str, near: int | None = None) -> QuoteMatch | None:
        quote = (quote or "").strip()
        if len(quote) < 2:
            return None

        # 1. exact (prefer the occurrence nearest to the hint, e.g. the chunk start)
        if near is not None:
            pos = self.text.find(quote, max(0, near))
            if pos == -1:
                pos = self.text.find(quote)
        else:
            pos = self.text.find(quote)
        if pos != -1:
            return QuoteMatch(pos, pos + len(quote), "exact")

        # 2. elided quote: parts must appear in order with bounded gaps
        if _ELLIPSIS.search(quote):
            parts = [p.strip(_EDGE) for p in _ELLIPSIS.split(quote)]
            parts = [normalize(p) for p in parts if len(p.strip(_EDGE)) >= 3]
            m = self._find_elided(parts)
            if m:
                return m

        # 3. normalized (whole quote, then with edge punctuation trimmed)
        for candidate in (quote, quote.strip(_EDGE)):
            nq = normalize(candidate)
            n = self._find_norm(nq)
            if n != -1:
                s, e = self._span(n, n + len(nq))
                return QuoteMatch(s, e, "exact" if self.text[s:e] == candidate else "normalized")
        return None

    def _find_elided(self, parts: list[str]) -> QuoteMatch | None:
        if len(parts) < 2:
            return None
        n0 = self._find_norm(parts[0])
        while n0 != -1:
            cur_end = n0 + len(parts[0])
            ok = True
            for p in parts[1:]:
                n = self._find_norm(p, cur_end)
                if n == -1 or n - cur_end > MAX_ELISION_GAP:
                    ok = False
                    break
                cur_end = n + len(p)
            if ok:
                s, e = self._span(n0, cur_end)
                return QuoteMatch(s, e, "elided")
            n0 = self._find_norm(parts[0], n0 + 1)
        return None

    def occurrences(self, surface: str, limit: int = 20) -> list[tuple[int, int]]:
        """All spans where a surface form (e.g. entity name) occurs, normalized match."""
        ns = normalize(surface)
        if len(ns) < 2:
            return []
        spans, n = [], self._find_norm(ns)
        while n != -1 and len(spans) < limit:
            spans.append(self._span(n, n + len(ns)))
            n = self._find_norm(ns, n + len(ns))
        return spans
