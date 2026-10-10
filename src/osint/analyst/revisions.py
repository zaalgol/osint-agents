"""Finding revisions: confidence changes and withdrawals, with history and approval.

Policy (cautious by default):
  * humans' revisions apply immediately (they are the approvers)
  * an analyst's (Claude's) *downgrade* applies immediately when
    analysis.auto_apply_downgrades is on: lowering confidence is the safe direction
  * an analyst's upgrade or withdrawal waits in the review queue for a human
Every revision keeps the old and new values, reason, supporting evidence and author.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.storage.db import EvidenceLink, Finding, FindingRevision, ReviewItem


class RevisionError(ValueError):
    pass


def propose_revision(s: Session, finding_id: int, new_confidence: float, reason: str, by: str,
                     evidence_ids: list[int] | None = None, withdraw: bool = False,
                     auto_apply_downgrades: bool = True,
                     investigation_id: int | None = None) -> dict:
    f = s.get(Finding, finding_id)
    if f is None or (investigation_id is not None and f.investigation_id != investigation_id):
        raise RevisionError(f"no finding {finding_id} in this investigation")
    if f.status == "withdrawn":
        raise RevisionError(f"finding {finding_id} is already withdrawn")
    if not 0 <= new_confidence <= 1:
        raise RevisionError("confidence must be between 0 and 1")
    if not reason or len(reason.strip()) < 10:
        raise RevisionError("give a reason (what evidence changes the confidence)")
    if not withdraw and abs(new_confidence - f.confidence) < 0.005:
        return {"finding": f"[F:{f.id}]", "status": "unchanged",
                "note": "same confidence as now: nothing to revise"}
    ev = list(dict.fromkeys(evidence_ids or []))
    if ev:
        found = set(s.scalars(select(EvidenceLink.id).where(EvidenceLink.id.in_(ev))))
        if missing := set(ev) - found:
            raise RevisionError(f"unknown evidence ids {sorted(missing)}")
    rev = FindingRevision(finding_id=f.id, old_confidence=f.confidence,
                          new_confidence=0.0 if withdraw else new_confidence, withdraw=withdraw,
                          reason=reason.strip(), evidence_ids=ev, proposed_by=by)
    s.add(rev)
    s.flush()
    human = by.startswith(("human:", "user:"))
    downgrade = not withdraw and new_confidence < f.confidence
    if human or (downgrade and auto_apply_downgrades):
        apply_revision(s, rev.id, by if human else f"auto:{by}")
        return {"revision_id": rev.id, "status": "applied",
                "finding": f"[F:{f.id}]", "confidence": f.confidence, "finding_status": f.status}
    item = ReviewItem(investigation_id=f.investigation_id, kind="finding_revision",
                      reason=(f"{'withdraw' if withdraw else 'revise'} [F:{f.id}] "
                              f"{rev.old_confidence:.2f} -> {rev.new_confidence:.2f}: {reason[:300]}"),
                      payload={"revision_id": rev.id, "finding_id": f.id, "finding_text": f.text,
                               "old": rev.old_confidence, "new": rev.new_confidence,
                               "withdraw": withdraw, "evidence_ids": ev},
                      created_by=by)
    s.add(item)
    s.flush()
    return {"revision_id": rev.id, "status": "proposed", "review_item": item.id,
            "note": "upgrades and withdrawals wait for human approval"}


def apply_revision(s: Session, revision_id: int, decided_by: str) -> FindingRevision:
    rev = s.get(FindingRevision, revision_id)
    if rev is None or rev.status != "proposed":
        raise RevisionError(f"revision {revision_id} is not pending")
    f = s.get(Finding, rev.finding_id)
    f.confidence = rev.new_confidence
    if rev.withdraw:
        f.status = "withdrawn"
    rev.status, rev.decided_by, rev.decided_at = "applied", decided_by, datetime.now(UTC)
    return rev


def reject_revision(s: Session, revision_id: int, decided_by: str) -> FindingRevision:
    rev = s.get(FindingRevision, revision_id)
    if rev is None or rev.status != "proposed":
        raise RevisionError(f"revision {revision_id} is not pending")
    rev.status, rev.decided_by, rev.decided_at = "rejected", decided_by, datetime.now(UTC)
    return rev


def history(s: Session, finding_id: int, limit: int = 5) -> list[dict]:
    return [{"revision": r.id, "from": r.old_confidence, "to": r.new_confidence,
             "withdraw": r.withdraw, "status": r.status, "reason": r.reason,
             "by": r.proposed_by, "decided_by": r.decided_by}
            for r in s.scalars(select(FindingRevision).where(
                FindingRevision.finding_id == finding_id)
                .order_by(FindingRevision.id.desc()).limit(limit))]
