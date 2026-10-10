"""Extraction evaluation against a hand-annotated gold set (evals/extraction/gold.jsonl).

Scores per model:
  entities   precision / recall / F1. A predicted entity matches a gold one with the same
             type family and a matching name (normalized, transliterated, fuzzy >= 0.9,
             aliases allowed)
  relations  P / R / F1. Same type (or parent/child type), both endpoints match
  events     P / R / F1. Same type and same date (when the gold has one)
  quotes     share of predicted quotes that verify verbatim against the text; this is
             the hallucinated-quote rate that the writer would reject
  relevance  accuracy of the relevant/irrelevant decision
Precision counts over-extraction (e.g. a relation from a denial) and recall counts misses.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from rapidfuzz import fuzz

from osint.core.config import project_home
from osint.core.models import DocumentView, ExtractionResult
from osint.core.ontology import Ontology
from osint.extraction.quotes import QuoteIndex
from osint.resolution.er import ascii_key

GOLD = Path("evals/extraction/gold.jsonl")


@dataclass
class PRF:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def p(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def r(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        return 2 * self.p * self.r / (self.p + self.r) if self.p + self.r else 0.0

    def add(self, other: PRF) -> None:
        self.tp, self.fp, self.fn = self.tp + other.tp, self.fp + other.fp, self.fn + other.fn

    def as_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "precision": round(self.p, 3),
                "recall": round(self.r, 3), "f1": round(self.f1, 3)}


@dataclass
class DocScore:
    id: str
    entities: PRF = field(default_factory=PRF)
    relations: PRF = field(default_factory=PRF)
    events: PRF = field(default_factory=PRF)
    quotes_total: int = 0
    quotes_verified: int = 0
    relevant_ok: bool = True
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


def load_gold(path: Path | None = None) -> list[dict]:
    p = path or project_home() / GOLD
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _names_match(a: str, b: str) -> bool:
    ka, kb = ascii_key(a), ascii_key(b)
    if not ka or not kb:
        return False
    return ka == kb or fuzz.ratio(ka, kb) >= 90 or (min(len(ka), len(kb)) >= 5 and (ka in kb or kb in ka))


def _family(onto: Ontology, t: str) -> str:
    if t not in onto.entity_types:
        return t
    chain = onto._ancestors(onto.entity_types, t)
    return chain[-1] if chain else t


def _type_ok(onto: Ontology, pred: str, gold: str) -> bool:
    if pred == gold:
        return True
    if gold in onto.entity_types and pred in onto.entity_types:
        return _family(onto, pred) == _family(onto, gold) or \
            {pred, gold} <= {"organization", "armed_group"}
    return False


def _rel_type_ok(onto: Ontology, pred: str, gold: str) -> bool:
    if pred == gold:
        return True
    def chain(t: str) -> list[str]:
        return [t, *onto._ancestors(onto.relation_types, t)] if t in onto.relation_types else [t]

    return gold in chain(pred) or pred in chain(gold)


def _match(preds: list, golds: list, same) -> PRF:
    used, tp = set(), 0
    for g in golds:
        for i, p in enumerate(preds):
            if i not in used and same(p, g):
                used.add(i)
                tp += 1
                break
    return PRF(tp=tp, fp=len(preds) - len(used), fn=len(golds) - tp)


def score_document(gold: dict, res: ExtractionResult, onto: Ontology) -> DocScore:
    ds = DocScore(gold["id"])
    ds.relevant_ok = res.relevant == gold["relevant"]
    if not res.relevant:
        res = ExtractionResult(relevant=False)

    def ent_same(p, g) -> bool:
        names = [g["name"], *g.get("aliases", [])]
        return _type_ok(onto, p.type, g["type"]) and any(_names_match(p.name, n) for n in names)

    def endpoint(name: str, gold_name: str) -> bool:
        gold_ent = next((e for e in gold["entities"] if e["name"] == gold_name), None)
        names = [gold_name, *(gold_ent or {}).get("aliases", [])]
        return any(_names_match(name, n) for n in names)

    def rel_same(p, g) -> bool:
        return (_rel_type_ok(onto, p.type, g["type"]) and endpoint(p.src.name, g["src"])
                and endpoint(p.dst.name, g["dst"]))

    def ev_same(p, g) -> bool:
        if p.type != g["type"]:
            return False
        return g["time"] is None or (p.time or "").startswith(g["time"])

    # entities: dedupe predictions by (type family, normalized name)
    seen, ents = set(), []
    for e in res.entities:
        key = (_family(onto, e.type), ascii_key(e.name))
        if key not in seen:
            seen.add(key)
            ents.append(e)
    ds.entities = _match(ents, gold["entities"], ent_same)
    facts = [r for r in res.relations if getattr(r, "stance", "asserted") in ("asserted", "reported")]
    ds.relations = _match(facts, gold["relations"], rel_same)
    ds.events = _match(res.events, gold["events"], ev_same)

    qi = QuoteIndex(gold["text"])
    quotes = [x.quote for x in [*res.entities, *res.relations, *res.events] if x.quote]
    ds.quotes_total = len(quotes)
    ds.quotes_verified = sum(1 for q in quotes if qi.find(q) is not None)
    return ds


@dataclass
class EvalRun:
    model: str
    role: str
    created_at: str
    docs: list[DocScore]
    extractor: str = ""

    def totals(self) -> dict:
        e, r, v = PRF(), PRF(), PRF()
        qt = qv = rel = 0
        for d in self.docs:
            e.add(d.entities)
            r.add(d.relations)
            v.add(d.events)
            qt += d.quotes_total
            qv += d.quotes_verified
            rel += int(d.relevant_ok)
        n = len(self.docs) or 1
        return {"entities": e.as_dict(), "relations": r.as_dict(), "events": v.as_dict(),
                "quote_verification_rate": round(qv / qt, 3) if qt else 1.0,
                "relevance_accuracy": round(rel / n, 3),
                "seconds_per_doc": round(sum(d.seconds for d in self.docs) / n, 1),
                "errors": sum(len(d.errors) for d in self.docs)}

    def as_dict(self) -> dict:
        return {"model": self.model, "role": self.role, "created_at": self.created_at,
                "extractor": self.extractor,
                "totals": self.totals(),
                "docs": [{**asdict(d), "entities": d.entities.as_dict(),
                          "relations": d.relations.as_dict(), "events": d.events.as_dict()}
                         for d in self.docs]}


async def run_extraction_eval(app, role: str = "agent", model: str | None = None,
                              gold_path: Path | None = None) -> EvalRun:
    from osint.core.config import get_models_config
    from osint.llm.local import LocalLLM
    from osint.plugins.extractors.llm import LLMExtractor

    cfg = get_models_config().local.model_copy(deep=True)
    if model:
        cfg.roles[role] = cfg.roles[role].model_copy(update={"model": model})
    llm = LocalLLM(cfg, slots=1)
    ext = LLMExtractor()
    ext.role = role
    app.settings.extraction.llm_role = role   # the eval decides the role, not settings
    ctx = app.context(None, with_db=False, llm=llm)
    docs = []
    try:
        for g in load_gold(gold_path):
            view = DocumentView(id=0, artifact_id=0, text=g["text"],
                                investigation_focus="terrorism, armed groups, attacks, threats, financing")
            t0 = time.monotonic()
            try:
                res = await ext.extract(view, ctx)
                ds = score_document(g, res, app.ontology)
            except Exception as e:  # noqa: BLE001 - a failed doc scores as all misses
                ds = DocScore(g["id"], entities=PRF(fn=len(g["entities"])),
                              relations=PRF(fn=len(g["relations"])),
                              events=PRF(fn=len(g["events"])), relevant_ok=False,
                              errors=[f"{type(e).__name__}: {e}"[:300]])
            ds.seconds = round(time.monotonic() - t0, 1)
            docs.append(ds)
    finally:
        await llm.aclose()
    return EvalRun(cfg.roles[role].model, role, datetime.now(UTC).isoformat(timespec="seconds"),
                   docs, extractor=ext.ident)


def save(app, run: EvalRun) -> Path:
    out = app.settings.data_path / "evals"
    out.mkdir(parents=True, exist_ok=True)
    safe = run.model.replace("/", "_").replace(":", "-")
    p = out / f"extraction-{safe}-{run.created_at.replace(':', '')}.json"
    p.write_text(json.dumps(run.as_dict(), indent=1, ensure_ascii=False), encoding="utf-8")
    return p


def history(app) -> list[dict]:
    out = app.settings.data_path / "evals"
    rows = []
    for p in sorted(out.glob("extraction-*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        rows.append({"file": p.name, "model": d["model"], "created_at": d["created_at"],
                     "extractor": d.get("extractor") or "extractor:llm@0.1.0",
                     **{k: v for k, v in d["totals"].items()}})
    return rows
