"""Hard purge: remove content that must not be kept (CSAM, malware, unlawful material).

Evidence is normally append-only. A purge is the one sanctioned exception, made under
the database's maintenance switch and recorded in the custody chain:

  * every stored file of the artifact (raw, WARC, screenshot, PDF, DOM) is deleted
  * extracted document text, translations, embeddings, mention contexts and evidence
    quotes are blanked
  * the hashes go on the local blocklist, so the same content is refused if seen again
  * a "purged" custody entry keeps the hashes, the reason and who did it, never content

Metadata rows stay (ids are referenced by findings and reports). Citations to a purged
artifact fail the report gate from then on, because the evidence can't be re-verified.
"""

from __future__ import annotations

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from osint.evidence import custody
from osint.storage.db import Artifact, Capture, Document, EvidenceLink, Mention
from osint.storage.raw_store import RawStore

PURGED = "[purged]"


def purged_hashes(session: Session) -> set[str]:
    """sha256 of every purged file (they're expected to be missing)."""
    from osint.storage.db import CustodyLog

    out: set[str] = set()
    for details in session.scalars(select(CustodyLog.details).where(CustodyLog.action == "purged")):
        out.update((details or {}).get("sha256s", []))
    return out


def purge_artifact(session: Session, store: RawStore, artifact_id: int, reason: str,
                   actor: str = "cli:purge") -> dict:
    """Purge in the caller's transaction; delete files only after the caller commits
    (call `delete_files` with the returned hashes)."""
    art = session.get(Artifact, artifact_id)
    if art is None:
        raise ValueError(f"artifact {artifact_id} not found")
    if not reason.strip():
        raise ValueError("a purge needs a reason (it is recorded in the custody chain)")
    hashes = [art.sha256, *session.scalars(select(Capture.sha256).where(
        Capture.artifact_id == artifact_id, Capture.sha256.is_not(None)))]
    hashes = list(dict.fromkeys(hashes))
    session.execute(text("SET LOCAL osint.maintenance = 'on'"))
    doc_ids = list(session.scalars(select(Document.id).where(Document.artifact_id == artifact_id)))
    if doc_ids:
        session.execute(update(Document).where(Document.id.in_(doc_ids)).values(
            text=PURGED, translated_text=None, embedding=None, title=None))
        session.execute(update(Mention).where(Mention.document_id.in_(doc_ids)).values(
            context=None, surface=PURGED))
    links = session.execute(update(EvidenceLink).where(EvidenceLink.artifact_id == artifact_id)
                            .values(quote_original=PURGED, quote_translated=None)).rowcount
    session.execute(text("SET LOCAL osint.maintenance = 'off'"))
    for h in hashes:
        store.blocklist.add(h, note=f"purged artifact {artifact_id}")
    custody.append(session, "purged", actor, artifact_id,
                   {"reason": reason, "sha256s": hashes, "documents": len(doc_ids),
                    "evidence_links": links})
    return {"artifact": artifact_id, "files": hashes, "documents": len(doc_ids),
            "evidence_links": links}


def delete_files(store: RawStore, hashes: list[str]) -> int:
    n = 0
    for h in hashes:
        if store.exists(h):
            store.purge(h)
            n += 1
    return n
