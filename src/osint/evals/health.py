"""Quality metrics on live data: extraction health per investigation, citation metrics per report."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from osint.storage.db import (
    EvidenceLink,
    InvestigationRef,
    Report,
    ReviewItem,
    SupportStats,
)


def extraction_health(s: Session, inv_id: int | None = None) -> dict:
    """How often the gatekeepers fired, relative to what got through."""
    rq = select(ReviewItem.kind, func.count()).group_by(ReviewItem.kind)
    if inv_id is not None:
        rq = rq.where(ReviewItem.investigation_id == inv_id)
    kinds = dict(s.execute(rq).all())
    eq = select(func.count()).select_from(EvidenceLink).where(
        EvidenceLink.target_type.in_(["relation", "event"]))
    sq = select(SupportStats.independent_sources)
    if inv_id is not None:
        docs = select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv_id, InvestigationRef.object_type == "document")
        eq = eq.where(EvidenceLink.document_id.in_(docs))
        rels = select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv_id,
            InvestigationRef.object_type.in_(["relation", "event"]))
        sq = sq.where(SupportStats.target_id.in_(rels))
    accepted = s.scalar(eq) or 0
    rejected = {k: kinds.get(k, 0) for k in ("quote_not_found", "weak_citation", "ontology",
                                             "unresolved")}
    total = accepted + sum(rejected.values())
    support = list(s.scalars(sq))
    return {
        "citations_accepted": accepted,
        "rejected": rejected,
        "rejection_rate": round(sum(rejected.values()) / total, 3) if total else 0.0,
        "hallucinated_quote_rate": round(rejected["quote_not_found"] / total, 3) if total else 0.0,
        "single_source_share": round(sum(1 for x in support if x <= 1) / len(support), 3)
        if support else None,
        "facts_with_2plus_sources": sum(1 for x in support if x >= 2),
        "open_review": {k: v for k, v in kinds.items()},
    }


def report_metrics(s: Session, inv_id: int | None = None) -> list[dict]:
    q = select(Report).order_by(Report.id)
    if inv_id is not None:
        q = q.where(Report.investigation_id == inv_id)
    out = []
    for r in s.scalars(q):
        v = r.verification or {}
        if "sentences" not in v:
            continue
        cited = v.get("cited", 0)
        checkable = cited + v.get("uncited", 0)
        bad = v.get("unsupported", 0) + v.get("partial", 0)
        out.append({
            "report": r.id, "investigation": r.investigation_id, "status": r.status,
            "sentences": v["sentences"],
            "citation_coverage": round(cited / checkable, 3) if checkable else 1.0,
            "citation_precision": round((cited - bad) / cited, 3) if cited else 1.0,
            "unresolved_markers": v.get("unresolved", 0),
            "single_source_sentences": v.get("single_source", 0),
            "supersedes": r.supersedes_id,
        })
    return out
