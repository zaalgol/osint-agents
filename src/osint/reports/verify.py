"""verify-report: the citation gate a report must pass before it can be final.

Checks, per sentence:
  1. resolution: every [E:n] is a verified evidence_link whose artifact file still
     re-hashes correctly; every [F:n] is a finding in this investigation
  2. coverage: every factual sentence carries at least one marker (sections like
     Methodology / Limitations / Sources are exempt)
  3. support: a local-LLM judge decides whether the cited quotes (or findings) support
     the sentence: supported | partial | unsupported
  4. single source: all of a sentence's evidence comes from one source domain (warning)

ok = no unresolved markers, no uncited factual sentences, no unsupported sentences.
"partial" and "single_source" are warnings for the analyst (citation_audit job).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from osint.storage.db import Artifact, EvidenceLink, Finding
from osint.storage.raw_store import IntegrityError, RawStore

MARKER = re.compile(r"\[(E|F):(\d+)\]")
EXEMPT_HEADING = re.compile(
    r"method|limitation|scope|source|reference|appendix|citation|glossary|evidence table|"
    r"about this report|caveat", re.IGNORECASE)
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[\"'\u201c(\[A-Z0-9])")
MIN_WORDS = 5


class SupportVerdict(BaseModel):
    verdict: Literal["supported", "partial", "unsupported"]
    missing: str  # what the claim says that the evidence does not


Judge = Callable[[str, str], Awaitable[SupportVerdict]]


@dataclass
class SentenceCheck:
    index: int
    section: str
    text: str
    markers: list[str]
    issues: list[str] = field(default_factory=list)
    verdict: str | None = None
    missing: str | None = None


@dataclass
class Verification:
    ok: bool
    sentences: int
    cited: int
    unresolved: int
    uncited: int
    unsupported: int
    partial: int
    single_source: int
    checks: list[SentenceCheck]
    report_sha256: str

    def as_dict(self, issues_only: bool = True) -> dict:
        d = asdict(self)
        if issues_only:
            d["checks"] = [asdict(c) for c in self.checks if c.issues]
        return d

    def summary(self) -> str:
        state = "PASS" if self.ok else "FAIL"
        return (f"{state}: {self.sentences} sentences, {self.cited} cited, "
                f"{self.unresolved} unresolved markers, {self.uncited} uncited, "
                f"{self.unsupported} unsupported, {self.partial} partial, "
                f"{self.single_source} single-source")


# --------------------------------------------------------------------------- parsing


def split_sentences(markdown: str) -> list[tuple[str, str]]:
    """Return (section heading, sentence) pairs for checkable prose, tables and lists."""
    out: list[tuple[str, str]] = []
    section = ""
    in_code = False
    para: list[str] = []

    def flush() -> None:
        if not para:
            return
        text = " ".join(para).strip()
        para.clear()
        pieces = SENTENCE_SPLIT.split(text)
        merged: list[str] = []
        for p in pieces:
            # a fragment that is only markers belongs to the previous sentence
            if merged and not MARKER.sub("", p).strip(" .;,"):
                merged[-1] += " " + p
            else:
                merged.append(p)
        out.extend((section, m.strip()) for m in merged if m.strip())

    for raw in markdown.splitlines():
        line = raw.rstrip()
        if line.strip().startswith("```"):
            flush()
            in_code = not in_code
            continue
        if in_code:
            continue
        if line.startswith("#"):
            flush()
            section = line.lstrip("#").strip()
            continue
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if re.fullmatch(r"\|?[\s:\-|]+\|?", stripped):  # table separator row
            continue
        if stripped.startswith("|"):
            flush()
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            out.append((section, " | ".join(c for c in cells if c)))
            continue
        m = re.match(r"^(\s*[-*+]|\s*\d+[.)])\s+(.*)", line)
        if m:
            flush()
            para.append(m.group(2))
            flush()
            continue
        if stripped.startswith(">"):
            stripped = stripped.lstrip("> ")
        para.append(stripped)
    flush()
    return out


def is_exempt(section: str, sentence: str) -> bool:
    if EXEMPT_HEADING.search(section or ""):
        return True
    bare = MARKER.sub("", sentence).strip()
    if bare.endswith("?") or len(bare.split()) < MIN_WORDS:
        return True
    return bool(re.fullmatch(r"[*_`\s]*[\w\s]+:[*_`\s]*", bare))  # label-only lines


# --------------------------------------------------------------------------- verification


class _Resolver:
    def __init__(self, session: Session, store: RawStore, investigation_id: int):
        self.s = session
        self.store = store
        self.inv = investigation_id
        self._ev: dict[int, tuple[EvidenceLink, Artifact] | None] = {}
        self._f: dict[int, Finding | None] = {}
        self._hash_ok: dict[int, bool] = {}

    def evidence(self, eid: int) -> tuple[EvidenceLink, Artifact] | None:
        if eid not in self._ev:
            row = self.s.execute(
                select(EvidenceLink, Artifact).join(Artifact, Artifact.id == EvidenceLink.artifact_id)
                .where(EvidenceLink.id == eid)).first()
            self._ev[eid] = (row[0], row[1]) if row else None
        return self._ev[eid]

    def artifact_intact(self, art: Artifact) -> bool:
        if art.id not in self._hash_ok:
            try:
                self.store.verify(art.sha256, art.sha512)
                self._hash_ok[art.id] = True
            except IntegrityError:
                self._hash_ok[art.id] = False
        return self._hash_ok[art.id]

    def retracted(self, eid: int) -> bool:
        from osint.storage.db import CitationRetraction

        return self.s.get(CitationRetraction, eid) is not None

    def finding(self, fid: int) -> Finding | None:
        if fid not in self._f:
            f = self.s.get(Finding, fid)
            ok = f is not None and f.investigation_id == self.inv and f.status != "withdrawn"
            self._f[fid] = f if ok else None   # withdrawn findings can't be cited
        return self._f[fid]

    def finding_quotes(self, fid: int) -> list[str]:
        rows = self.s.scalars(select(EvidenceLink.quote_original).where(
            EvidenceLink.target_type == "finding", EvidenceLink.target_id == fid).limit(5))
        return [q for q in rows if q]


async def verify_report(
    session_factory: sessionmaker[Session], store: RawStore, investigation_id: int,
    markdown: str, judge: Judge | None = None, max_parallel: int = 4,
) -> Verification:
    sentences = split_sentences(markdown)
    checks: list[SentenceCheck] = []
    judge_jobs: list[tuple[SentenceCheck, str]] = []

    with session_factory() as s:
        res = _Resolver(s, store, investigation_id)
        for i, (section, text) in enumerate(sentences):
            markers = [f"{k}:{n}" for k, n in MARKER.findall(text)]
            c = SentenceCheck(i, section, text, markers)
            checks.append(c)
            if not markers:
                if not is_exempt(section, text):
                    c.issues.append("uncited")
                continue
            evidence_texts, domains = [], set()
            for m in markers:
                kind, num = m.split(":")
                n = int(num)
                if kind == "E":
                    row = res.evidence(n)
                    if row is None:
                        c.issues.append(f"unresolved:{m}")
                        continue
                    ev, art = row
                    if res.retracted(n):
                        c.issues.append(f"unresolved:{m} (citation retracted)")
                        continue
                    if not ev.quote_verified:
                        c.issues.append(f"unverified_quote:{m}")
                    if not res.artifact_intact(art):
                        c.issues.append(f"integrity:{m}")
                    evidence_texts.append(f"[{m}] {ev.quote_original or ev.media_locator}")
                    domains.add(urlsplit(art.final_url or art.url or "").hostname or f"a{art.id}")
                else:
                    f = res.finding(n)
                    if f is None:
                        c.issues.append(f"unresolved:{m}")
                        continue
                    quotes = "; ".join(f'"{q}"' for q in res.finding_quotes(n))
                    evidence_texts.append(
                        f"[{m}] FINDING ({f.epistemic_status}, confidence {f.confidence:.2f}): "
                        f"{f.text}" + (f" Supporting quotes: {quotes}" if quotes else ""))
                    domains.add(f"finding:{n}")
            if len(domains) == 1 and all(m.startswith("E:") for m in markers):
                c.issues.append("single_source")
            if judge is not None and evidence_texts and not is_exempt(section, text):
                judge_jobs.append((c, "\n".join(evidence_texts)))

    if judge is not None and judge_jobs:
        sem = asyncio.Semaphore(max_parallel)

        async def run(c: SentenceCheck, evidence: str) -> None:
            async with sem:
                v = await judge(MARKER.sub("", c.text).strip(), evidence)
            c.verdict, c.missing = v.verdict, v.missing
            if v.verdict != "supported":
                c.issues.append(v.verdict)

        await asyncio.gather(*(run(c, e) for c, e in judge_jobs))

    def count(prefix: str) -> int:
        return sum(1 for c in checks for i in c.issues if i.startswith(prefix))

    unresolved = count("unresolved") + count("integrity") + count("unverified_quote")
    uncited, unsupported = count("uncited"), count("unsupported")
    return Verification(
        ok=unresolved == 0 and uncited == 0 and unsupported == 0,
        sentences=len(checks),
        cited=sum(1 for c in checks if c.markers),
        unresolved=unresolved, uncited=uncited, unsupported=unsupported,
        partial=count("partial"), single_source=count("single_source"),
        checks=checks,
        report_sha256=hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
    )


# --------------------------------------------------------------------------- LLM judge

JUDGE_SYSTEM = """You check citations in an intelligence report. Given a CLAIM and the \
EVIDENCE cited for it, decide whether the evidence supports the claim.
- supported: everything the claim asserts is stated in, or directly follows from, the \
evidence (paraphrase and translation are fine; hedged analytic wording like "likely" is \
fine when the evidence or cited finding supports that level of confidence).
- partial: some of the claim is supported, but it adds facts, numbers, names, dates or \
certainty that the evidence does not contain.
- unsupported: the evidence does not state the claim, or contradicts it.
Judge only against the evidence shown, never outside knowledge. In "missing", name exactly \
what is not supported (empty string if supported)."""


def llm_judge(llm, role: str = "agent") -> Judge:
    cache: dict[str, SupportVerdict] = {}

    async def judge(claim: str, evidence: str) -> SupportVerdict:
        key = hashlib.sha256(f"{claim}\x00{evidence}".encode()).hexdigest()
        if key not in cache:
            cache[key] = await llm.chat_json(
                role, JUDGE_SYSTEM, f"CLAIM:\n{claim}\n\nEVIDENCE:\n{evidence}", SupportVerdict)
        return cache[key]

    return judge
