"""Knowledge-base tools for the Claude analyst (exposed over MCP by osint.mcp_server).

Read tools return compact, citation-ready records (quotes with [E:n] markers, never raw
pages). Read access is global, so the analyst can see connections to other
investigations. Write tools are scoped to the job's investigation and enforce the
proof rules: no finding without evidence or premises, no collection request outside the
budget, and no report marked verified unless it passes the citation gate.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError as MCPToolError
from pydantic import ValidationError
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from osint.core.models import Citation, EpistemicStatus, FindingIn, PremiseType, TaskSpec
from osint.core.ontology import Ontology
from osint.core.plugins import PluginRegistry
from osint.extraction.retract import active, valid_citation
from osint.orchestrator import queue
from osint.reports.verify import Judge, verify_report
from osint.storage.db import (
    Artifact,
    CrossLink,
    Document,
    Entity,
    EntityAlias,
    Event,
    EventParticipant,
    EvidenceLink,
    Finding,
    Inference,
    InferencePremise,
    Investigation,
    InvestigationRef,
    Relation,
    Report,
    ReviewItem,
    SupportStats,
    Task,
)
from osint.storage.raw_store import RawStore
from osint.text.normalize import name_key

MAX_READ_CHARS = 8000


class ToolError(MCPToolError, ValueError):
    """Shown to the analyst as a tool error. The message says how to fix the call.

    Subclasses the MCP SDK's ToolError: the SDK hides the text of any other exception
    from the model, and these messages are the analyst's instructions for retrying.
    """


@dataclass
class AnalystTools:
    session_factory: sessionmaker[Session]
    ontology: Ontology
    registry: PluginRegistry
    raw_store: RawStore
    investigation_id: int            # writes are scoped to this investigation
    actor: str = "claude:analyst"
    max_collection_requests: int = 30
    judge: Judge | None = None
    neo4j: Any = None                # Neo4jSettings; graph tools need it
    auto_apply_downgrades: bool = True
    _requests: int = field(default=0, init=False)
    _driver: Any = field(default=None, init=False)

    # ================================================================ helpers

    def _inv(self, s: Session, ref: int | str | None) -> Investigation:
        if ref is None:
            ref = self.investigation_id
        inv = s.get(Investigation, int(ref)) if str(ref).isdigit() else s.scalar(
            select(Investigation).where(Investigation.name == str(ref)))
        if inv is None:
            raise ToolError(f"no investigation {ref!r}")
        return inv

    def _refs(self, inv_id: int, object_type: str):
        return select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv_id,
            InvestigationRef.object_type == object_type)

    def _evidence_ids(self, s: Session, target_type: str, target_id: int, limit: int = 5) -> list[str]:
        ids = s.scalars(select(EvidenceLink.id).where(
            EvidenceLink.target_type == target_type, EvidenceLink.target_id == target_id,
            valid_citation()).order_by(EvidenceLink.id).limit(limit))
        return [f"[E:{i}]" for i in ids]

    def _support(self, s: Session, target_type: str, target_id: int) -> dict | None:
        st = s.get(SupportStats, (target_type, target_id))
        if st is None:
            return None
        out = {"independent_sources": st.independent_sources, "documents": st.documents}
        if st.contradicted_by:
            out["contradicted_by_events"] = list(st.contradicted_by)
        return out

    def _investigations_of(self, s: Session, entity_id: int) -> list[dict]:
        rows = s.execute(select(Investigation.id, Investigation.name).join(
            InvestigationRef, InvestigationRef.investigation_id == Investigation.id).where(
            InvestigationRef.object_type == "entity", InvestigationRef.object_id == entity_id))
        return [{"id": i, "name": n} for i, n in rows]

    # ================================================================ read tools

    def investigation_overview(self, investigation: int | str | None = None) -> dict:
        """Counts, seed, most connected entities, recent events, findings, cross-case overlap."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            counts = dict(s.execute(select(InvestigationRef.object_type, func.count()).where(
                InvestigationRef.investigation_id == inv.id).group_by(
                InvestigationRef.object_type)).all())
            ent_ids = self._refs(inv.id, "entity")
            degree = (
                select(Entity.id, Entity.canonical_name, Entity.type,
                       (select(func.count()).where(or_(Relation.src_entity_id == Entity.id,
                                                       Relation.dst_entity_id == Entity.id))
                        .scalar_subquery()
                        + select(func.count()).where(EventParticipant.entity_id == Entity.id)
                        .scalar_subquery()).label("deg"))
                .where(Entity.id.in_(ent_ids)).order_by(text("deg DESC")).limit(25))
            top = [{"entity_id": i, "name": n, "type": t, "links": d}
                   for i, n, t, d in s.execute(degree)]
            events = s.execute(select(Event).where(Event.id.in_(self._refs(inv.id, "event")))
                               .order_by(Event.time.desc().nulls_last()).limit(15)).scalars()
            ev = [{"event_id": e.id, "type": e.type, "time": e.time.date().isoformat()
                   if e.time else None, "description": e.description} for e in events]
            findings = s.scalar(select(func.count()).where(Finding.investigation_id == inv.id))
            review = s.scalar(select(func.count()).where(ReviewItem.investigation_id == inv.id,
                                                         ReviewItem.status == "open"))
            overlap = s.execute(
                select(InvestigationRef.investigation_id, func.count()).where(
                    InvestigationRef.object_type == "entity",
                    InvestigationRef.object_id.in_(ent_ids),
                    InvestigationRef.investigation_id != inv.id)
                .group_by(InvestigationRef.investigation_id)).all()
            tasks = dict(s.execute(select(Task.status, func.count()).where(
                Task.investigation_id == inv.id).group_by(Task.status)).all())
            return {
                "investigation": {"id": inv.id, "name": inv.name, "seed": inv.seed,
                                  "plan": (inv.config or {}).get("plan")},
                "counts": {**counts, "findings": findings, "open_review_items": review},
                "tasks": tasks,
                "top_entities": top,
                "recent_events": ev,
                "shared_entities_with_other_investigations": [
                    {"investigation_id": i, "shared_entities": n} for i, n in overlap],
            }

    def search_entities(self, query: str, type: str | None = None,
                        investigation: int | str | None = None, limit: int = 20) -> list[dict]:
        """Find entities by (normalized) name or alias, in all investigations by default."""
        with self.session_factory() as s:
            q = (select(Entity).join(EntityAlias, EntityAlias.entity_id == Entity.id)
                 .where(EntityAlias.alias_norm.contains(name_key(query)),
                        Entity.merged_into_id.is_(None)).distinct().limit(min(limit, 50)))
            if type:
                q = q.where(Entity.type == type)
            if investigation is not None:
                q = q.where(Entity.id.in_(self._refs(self._inv(s, investigation).id, "entity")))
            out = []
            for e in s.scalars(q):
                aliases = s.scalars(select(EntityAlias.alias).where(
                    EntityAlias.entity_id == e.id).limit(8)).all()
                out.append({"entity_id": e.id, "name": e.canonical_name, "type": e.type,
                            "aliases": sorted(set(aliases)),
                            "investigations": self._investigations_of(s, e.id)})
            return out

    def get_entity(self, entity_id: int) -> dict:
        """Entity with aliases, relations and events, each with evidence markers."""
        with self.session_factory() as s:
            e = s.get(Entity, entity_id)
            if e is None:
                raise ToolError(f"no entity {entity_id}")
            other = Entity.__table__.alias("other")
            rels = []
            for r, oid, oname, otype in s.execute(
                select(Relation, other.c.id, other.c.canonical_name, other.c.type)
                .join(other, other.c.id == Relation.dst_entity_id)
                .where(Relation.src_entity_id == e.id, active()).limit(50)):
                rels.append({"relation_id": r.id, "direction": "out", "type": r.type,
                             "other": {"entity_id": oid, "name": oname, "type": otype},
                             "confidence": r.confidence,
                             "evidence": self._evidence_ids(s, "relation", r.id),
                             "support": self._support(s, "relation", r.id)})
            for r, oid, oname, otype in s.execute(
                select(Relation, other.c.id, other.c.canonical_name, other.c.type)
                .join(other, other.c.id == Relation.src_entity_id)
                .where(Relation.dst_entity_id == e.id, active()).limit(50)):
                rels.append({"relation_id": r.id, "direction": "in", "type": r.type,
                             "other": {"entity_id": oid, "name": oname, "type": otype},
                             "confidence": r.confidence,
                             "evidence": self._evidence_ids(s, "relation", r.id),
                             "support": self._support(s, "relation", r.id)})
            events = []
            for ev, role in s.execute(
                select(Event, EventParticipant.role).join(
                    EventParticipant, EventParticipant.event_id == Event.id)
                .where(EventParticipant.entity_id == e.id).order_by(Event.time.desc().nulls_last())
                .limit(30)):
                events.append({"event_id": ev.id, "type": ev.type, "role": role,
                               "time": ev.time.date().isoformat() if ev.time else None,
                               "description": ev.description,
                               "evidence": self._evidence_ids(s, "event", ev.id),
                               "support": self._support(s, "event", ev.id)})
            from osint.storage.db import Claim

            claims = []
            for c in s.scalars(select(Claim).where(
                    ((Claim.subject_type == "entity") & (Claim.subject_id == e.id))
                    | ((Claim.object_type == "entity") & (Claim.object_id == e.id))).limit(30)):
                other_id = c.object_id if c.subject_id == e.id else c.subject_id
                other_e = s.get(Entity, other_id) if other_id else None
                claims.append({"claim_id": c.id, "stance": c.stance, "predicate": c.predicate,
                               "role": "subject" if c.subject_id == e.id else "object",
                               "other": other_e.canonical_name if other_e else None,
                               "evidence": self._evidence_ids(s, "claim", c.id)})
            mentions = s.scalar(select(func.count()).select_from(EntityAlias).where(
                EntityAlias.entity_id == e.id))
            return {"entity_id": e.id, "name": e.canonical_name, "type": e.type,
                    "strong_key": e.strong_key, "attributes": e.attributes,
                    "aliases": sorted(set(s.scalars(select(EntityAlias.alias).where(
                        EntityAlias.entity_id == e.id)))),
                    "alias_count": mentions,
                    "investigations": self._investigations_of(s, e.id),
                    "relations": rels, "events": events,
                    "claims_not_facts": claims}

    def neighborhood(self, entity_ids: list[int], hops: int = 1,
                     investigation: int | str | None = None, max_edges: int = 200) -> dict:
        """Graph around entities: relations and event co-participation, up to 2 hops."""
        hops = max(1, min(hops, 2))
        with self.session_factory() as s:
            scope = None
            if investigation is not None:
                scope = self._refs(self._inv(s, investigation).id, "relation")
            frontier, seen = set(entity_ids), set(entity_ids)
            edges: list[dict] = []
            for _ in range(hops):
                q = select(Relation).where(or_(Relation.src_entity_id.in_(frontier),
                                               Relation.dst_entity_id.in_(frontier)), active())
                if scope is not None:
                    q = q.where(Relation.id.in_(scope))
                nxt = set()
                for r in s.scalars(q.limit(max_edges)):
                    edges.append({"relation_id": r.id, "type": r.type, "src": r.src_entity_id,
                                  "dst": r.dst_entity_id, "confidence": r.confidence,
                                  "evidence": self._evidence_ids(s, "relation", r.id, 3)})
                    nxt |= {r.src_entity_id, r.dst_entity_id}
                co = select(EventParticipant.event_id).where(
                    EventParticipant.entity_id.in_(frontier))
                for ev_id, ent_id in s.execute(select(EventParticipant.event_id,
                                                      EventParticipant.entity_id)
                                               .where(EventParticipant.event_id.in_(co))
                                               .limit(max_edges)):
                    nxt.add(ent_id)
                    edges.append({"event_id": ev_id, "type": "event_participant",
                                  "entity": ent_id})
                frontier = nxt - seen
                seen |= nxt
            nodes = [{"entity_id": e.id, "name": e.canonical_name, "type": e.type}
                     for e in s.scalars(select(Entity).where(Entity.id.in_(seen)))]
            uniq = {str(sorted(e.items())): e for e in edges}
            return {"nodes": nodes, "edges": list(uniq.values())[:max_edges]}

    def search_documents(self, query: str, investigation: int | str | None = None,
                         limit: int = 10) -> list[dict]:
        """Full-text search over collected documents; returns snippets, not whole texts."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            tsq = func.websearch_to_tsquery("simple", query)
            vec = func.to_tsvector("simple", Document.text)
            q = (select(Document, Artifact,
                        func.ts_headline("simple", Document.text, tsq,
                                         "MaxWords=45, MinWords=20, MaxFragments=2"),
                        func.ts_rank(vec, tsq).label("rank"))
                 .join(Artifact, Artifact.id == Document.artifact_id)
                 .where(vec.op("@@")(tsq), Document.id.in_(self._refs(inv.id, "document")))
                 .order_by(text("rank DESC")).limit(min(limit, 30)))
            return [{"document_id": d.id, "title": d.title, "url": a.final_url or a.url,
                     "published_at": d.published_at.isoformat() if d.published_at else None,
                     "chars": len(d.text), "snippet": snip}
                    for d, a, snip, _ in s.execute(q)]

    def read_document(self, document_id: int, start: int = 0, length: int = 4000) -> dict:
        """Read a window of a document's text (max 8000 chars per call)."""
        with self.session_factory() as s:
            d = s.get(Document, document_id)
            if d is None:
                raise ToolError(f"no document {document_id}")
            a = s.get(Artifact, d.artifact_id)
            length = max(200, min(length, MAX_READ_CHARS))
            start = max(0, min(start, len(d.text)))
            return {"document_id": d.id, "title": d.title, "url": a.final_url or a.url,
                    "captured_at": a.fetched_at_utc.isoformat(), "total_chars": len(d.text),
                    "start": start, "end": min(len(d.text), start + length),
                    "text": d.text[start:start + length],
                    "note": "To cite, use evidence markers from get_evidence / get_entity; "
                            "raw document text is not itself a citation."}

    def get_evidence(self, evidence_ids: list[int], context_chars: int = 300) -> list[dict]:
        """Full citation records for [E:n] markers: quote, source, capture time, hash, context."""
        with self.session_factory() as s:
            out = []
            for eid in evidence_ids[:50]:
                row = s.execute(select(EvidenceLink, Artifact).join(
                    Artifact, Artifact.id == EvidenceLink.artifact_id)
                    .where(EvidenceLink.id == eid)).first()
                if row is None:
                    out.append({"marker": f"[E:{eid}]", "error": "no such evidence"})
                    continue
                ev, art = row
                from osint.storage.db import CitationRetraction

                retracted = s.get(CitationRetraction, ev.id)
                if retracted is not None:
                    out.append({"marker": f"[E:{ev.id}]", "error": "citation retracted: "
                                f"{retracted.reason}; do not cite"})
                    continue
                ctx = None
                doc = s.get(Document, ev.document_id) if ev.document_id else None
                if doc is not None and ev.char_start is not None:
                    a, b = max(0, ev.char_start - context_chars), ev.char_end + context_chars
                    ctx = doc.text[a:b]
                from osint.evidence.sources import credibility, grade_of

                grade = grade_of(s, art.source_id)
                cred = credibility(s, ev.target_type, ev.target_id)
                invs = [{"id": i, "name": n} for i, n in s.execute(
                    select(Investigation.id, Investigation.name).join(
                        InvestigationRef, InvestigationRef.investigation_id == Investigation.id)
                    .where(InvestigationRef.object_type == "artifact",
                           InvestigationRef.object_id == art.id))]
                out.append({
                    "marker": f"[E:{ev.id}]", "quote": ev.quote_original,
                    "collected_in": invs,
                    "quote_translated": ev.quote_translated, "verified": ev.quote_verified,
                    "cites": {"type": ev.target_type, "id": ev.target_id},
                    "document_id": ev.document_id, "title": doc.title if doc else None,
                    "url": art.final_url or art.url,
                    "posted_at": art.posted_at.isoformat() if art.posted_at else None,
                    "captured_at": art.fetched_at_utc.isoformat(), "sha256": art.sha256,
                    "source_reliability": grade, "information_credibility": cred,
                    "admiralty": grade + cred, "context": ctx,
                })
            return out

    def timeline(self, investigation: int | str | None = None, start: str | None = None,
                 end: str | None = None, limit: int = 100) -> list[dict]:
        """Events in time order, with participants and evidence markers."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            q = select(Event).where(Event.id.in_(self._refs(inv.id, "event")),
                                    # one row per incident: hide non-canonical cluster members
                                    (Event.cluster_id.is_(None)) | (Event.cluster_id == Event.id))
            if start:
                q = q.where(Event.time >= start)
            if end:
                q = q.where(Event.time <= end)
            out = []
            for ev in s.scalars(q.order_by(Event.time.asc().nulls_last()).limit(min(limit, 300))):
                parts = s.execute(select(Entity.id, Entity.canonical_name, EventParticipant.role)
                                  .join(EventParticipant, EventParticipant.entity_id == Entity.id)
                                  .where(EventParticipant.event_id == ev.id)).all()
                loc = s.get(Entity, ev.location_entity_id) if ev.location_entity_id else None
                members = [ev.id]
                if ev.cluster_id is not None:
                    members = list(s.scalars(select(Event.id).where(
                        Event.cluster_id == ev.cluster_id).order_by(Event.id)))
                evidence = []
                for m in members:
                    evidence += self._evidence_ids(s, "event", m, 3)
                out.append({"event_id": ev.id, "reports": len(members),
                            "same_incident_events": members if len(members) > 1 else None,
                            "type": ev.type,
                            "time": ev.time.isoformat() if ev.time else None,
                            "precision": ev.time_precision, "description": ev.description,
                            "location": loc.canonical_name if loc else None,
                            "participants": [{"entity_id": i, "name": n, "role": r}
                                             for i, n, r in parts],
                            "evidence": evidence[:8],
                            "support": self._support(s, "event", ev.id)})
            return out

    def list_findings(self, investigation: int | str | None = None) -> list[dict]:
        """Findings recorded so far, with [F:n] markers and their evidence."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            out = []
            from osint.analyst.revisions import history

            for f in s.scalars(select(Finding).where(Finding.investigation_id == inv.id)
                               .order_by(Finding.id)):
                row = {"marker": f"[F:{f.id}]", "kind": f.kind, "text": f.text,
                       "confidence": f.confidence, "epistemic_status": f.epistemic_status,
                       "status": f.status, "created_by": f.created_by,
                       "evidence": self._evidence_ids(s, "finding", f.id, 10)}
                if revs := history(s, f.id, 3):
                    row["revisions"] = revs
                out.append(row)
            return out

    def shared_entities(self, investigation: int | str | None = None, limit: int = 50) -> list[dict]:
        """Entities of this investigation that also appear in other investigations."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            rows = s.execute(
                select(Entity.id, Entity.canonical_name, Entity.type,
                       func.array_agg(InvestigationRef.investigation_id.distinct()))
                .join(InvestigationRef, (InvestigationRef.object_type == "entity")
                      & (InvestigationRef.object_id == Entity.id))
                .where(Entity.id.in_(self._refs(inv.id, "entity")),
                       InvestigationRef.investigation_id != inv.id)
                .group_by(Entity.id).limit(limit))
            return [{"entity_id": i, "name": n, "type": t, "other_investigations": sorted(o)}
                    for i, n, t, o in rows]

    def cross_links(self, investigation: int | str | None = None, status: str | None = None,
                    limit: int = 50) -> list[dict]:
        """Links between this investigation and others (candidates, confirmed, rejected)."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            q = select(CrossLink).where((CrossLink.investigation_a == inv.id)
                                        | (CrossLink.investigation_b == inv.id))
            if status:
                q = q.where(CrossLink.status == status)
            out = []
            for c in s.scalars(q.order_by(CrossLink.score.desc()).limit(min(limit, 200))):
                other = c.investigation_b if c.investigation_a == inv.id else c.investigation_a
                oname = s.scalar(select(Investigation.name).where(Investigation.id == other))
                via: dict = {"type": c.via_type, "id": c.via_id}
                if c.via_type == "entity" and (e := s.get(Entity, c.via_id)):
                    via |= {"name": e.canonical_name, "entity_type": e.type}
                elif c.via_type == "event" and (ev := s.get(Event, c.via_id)):
                    via |= {"description": ev.description}
                out.append({"link_id": c.id, "other_investigation": {"id": other, "name": oname},
                            "tier": c.tier, "score": c.score, "status": c.status, "via": via,
                            "explanation": c.explanation, "decided_by": c.decided_by,
                            "evidence": self._evidence_ids(s, "cross_link", c.id)})
            return out

    def _graph(self):
        if self.neo4j is None:
            raise ToolError("graph database not configured")
        if self._driver is None:
            from osint.storage.graph import make_driver

            self._driver = make_driver(self.neo4j)
        return self._driver

    def key_players(self, investigation: int | str | None = None, top: int = 15) -> dict:
        """Most central entities (brokers, hubs) and communities in the link network."""
        from osint.linking.network import key_players

        with self.session_factory() as s:
            inv = self._inv(s, investigation) if investigation != "all" else None
            return key_players(s, inv.id if inv else None, top)

    def shortest_path(self, entity_a: int, entity_b: int, max_hops: int = 6) -> dict:
        """How two entities connect, across all investigations (graph projection)."""
        from osint.storage.graph import shortest_path

        rows = shortest_path(self._graph(), entity_a, entity_b, max_hops)
        if not rows:
            return {"connected": False, "note": f"no path within {max_hops} hops "
                                                "(run `osint graph-sync` if data is new)"}
        return {"connected": True, **rows[0],
                "note": "relation_ids can be expanded with get_entity for evidence"}

    def graph_query(self, cypher: str, params: dict | None = None) -> list[dict]:
        """Read-only Cypher over the graph projection (max 200 rows)."""
        from osint.storage.graph import read_query

        try:
            return read_query(self._graph(), cypher, params)
        except ValueError as e:
            raise ToolError(str(e)) from e
        except Exception as e:
            raise ToolError(f"cypher error: {str(e)[:500]}") from e

    def contradictions(self, investigation: int | str | None = None) -> list[dict]:
        """Events reported with conflicting facts (e.g. different dates for one incident)."""
        with self.session_factory() as s:
            inv = self._inv(s, investigation)
            ev_ids = set(s.scalars(self._refs(inv.id, "event")))
            out = []
            for r in s.scalars(select(ReviewItem).where(ReviewItem.kind == "contradiction")):
                if {r.payload["a"], r.payload["b"]} & ev_ids:
                    out.append({"events": [r.payload["a"], r.payload["b"]], "issue": r.reason,
                                "a": r.payload.get("a_description"),
                                "b": r.payload.get("b_description"), "status": r.status,
                                "evidence_a": self._evidence_ids(s, "event", r.payload["a"]),
                                "evidence_b": self._evidence_ids(s, "event", r.payload["b"])})
            return out

    # ================================================================ write tools

    def add_finding(self, text: str, kind: str, confidence: float, epistemic_status: str,
                    evidence_ids: list[int] | None = None, premises: list[dict] | None = None,
                    method: str | None = None) -> dict:
        """Record a finding with proof. Returns its [F:n] marker for use in reports."""
        evidence_ids = list(dict.fromkeys(evidence_ids or []))
        premises = premises or []
        try:
            status = EpistemicStatus(epistemic_status)
            prem = [(PremiseType(p["type"]), int(p["id"])) for p in premises]
        except (ValueError, KeyError, TypeError) as e:
            raise ToolError(f"bad epistemic_status or premise ({e}); premise = "
                            '{"type": "evidence|claim|relation|event|finding", "id": n}') from e
        try:
            # one transaction; the DB's proof triggers fire at COMMIT (end of this block)
            with self.session_factory() as s, s.begin():
                sources = s.scalars(
                    select(EvidenceLink).where(EvidenceLink.id.in_(evidence_ids))).all()
                missing = set(evidence_ids) - {e.id for e in sources}
                if missing:
                    raise ToolError(f"unknown evidence ids {sorted(missing)}; use ids returned "
                                    "by get_entity / timeline / get_evidence")
                inferential = status in (EpistemicStatus.INFERRED, EpistemicStatus.ASSESSED)
                try:
                    FindingIn(investigation_id=self.investigation_id, kind=kind, text=text,
                              confidence=confidence, epistemic_status=status,
                              created_by=self.actor,
                              citations=[Citation(artifact_id=e.artifact_id,
                                                  quote_original=e.quote_original,
                                                  media_locator=e.media_locator)
                                         for e in sources],
                              premises=prem + ([(PremiseType.EVIDENCE, e.id) for e in sources]
                                               if inferential else []),
                              method=method)
                except ValidationError as e:
                    raise ToolError(e.errors()[0]["msg"]) from e
                f = Finding(investigation_id=self.investigation_id, kind=kind, text=text,
                            confidence=confidence, epistemic_status=status.value,
                            created_by=self.actor)
                s.add(f)
                s.flush()
                for src in sources:  # the finding's own citations point at the same spans
                    s.add(EvidenceLink(
                        target_type="finding", target_id=f.id, artifact_id=src.artifact_id,
                        document_id=src.document_id, quote_original=src.quote_original,
                        quote_translated=src.quote_translated, translator=src.translator,
                        char_start=src.char_start, char_end=src.char_end,
                        media_locator=src.media_locator, quote_verified=src.quote_verified,
                        verified_at=src.verified_at, created_by=f"{self.actor} via E:{src.id}"))
                if prem or inferential:
                    inf = Inference(conclusion_type="finding", conclusion_id=f.id,
                                    method=method or "analyst judgement",
                                    confidence=confidence, created_by=self.actor)
                    s.add(inf)
                    s.flush()
                    keys = {(p.value, i) for p, i in prem} | {("evidence", e.id) for e in sources}
                    for ptype, pid in keys:
                        s.add(InferencePremise(inference_id=inf.id, premise_type=ptype,
                                               premise_id=pid))
                fid = f.id
        except DBAPIError as e:
            raise ToolError(f"rejected by integrity rules: {str(e.orig).splitlines()[0]}") from e
        return {"finding_id": fid, "marker": f"[F:{fid}]"}

    def request_collection(self, plugin: str, params: dict[str, Any], reason: str,
                           priority: int = 100) -> dict:
        """Ask the local agents to collect more (search queries, URLs, feeds)."""
        if self._requests >= self.max_collection_requests:
            raise ToolError(f"collection request budget ({self.max_collection_requests}) used up")
        try:
            cls = self.registry.get("collector", plugin)
        except Exception as e:
            names = [c.name for c, _ in self.registry.list("collector")]
            raise ToolError(f"unknown collector {plugin!r}; available: {names}") from e
        if getattr(cls, "requires_account", False):
            raise ToolError(f"collector {plugin!r} needs the user's account and is disabled; "
                            "use public sources")
        try:
            cls.params_schema.model_validate(params)
        except ValidationError as e:
            raise ToolError(f"invalid params for {plugin}: {e.errors()[0]}; schema: "
                            f"{cls.params_schema.model_json_schema()}") from e
        with self.session_factory() as s, s.begin():
            tid, created = queue.enqueue(s, TaskSpec(
                investigation_id=self.investigation_id, type="collect", plugin=plugin,
                params={**params, "_requested_by": self.actor, "_reason": reason[:500]},
                priority=max(10, min(priority, 200))))
        self._requests += int(created)
        return {"task_id": tid, "queued": created,
                "note": "runs on the next `osint run`; not yet available to this job"}

    async def write_report(self, title: str, markdown: str, supersedes_id: int | None = None) -> dict:
        """Save a report version and run the citation gate. Fix and resubmit until it passes."""
        with self.session_factory() as s, s.begin():
            r = Report(investigation_id=self.investigation_id, title=title, markdown=markdown,
                       status="draft", created_by=self.actor, supersedes_id=supersedes_id)
            s.add(r)
            s.flush()
            rid = r.id
        return await self.verify_report(rid)

    async def verify_report(self, report_id: int) -> dict:
        """Re-run the citation gate on a stored report."""
        with self.session_factory() as s:
            r = s.get(Report, report_id)
            if r is None or r.investigation_id != self.investigation_id:
                raise ToolError(f"no report {report_id} in this investigation")
            md_text = r.markdown
        v = await verify_report(self.session_factory, self.raw_store, self.investigation_id,
                                md_text, judge=self.judge)
        with self.session_factory() as s, s.begin():
            r = s.get(Report, report_id)
            r.verification = {**v.as_dict(), "summary": v.summary()}
            if r.status in ("draft", "verified"):
                r.status = "verified" if v.ok else "draft"
        issues = [{"sentence": c.index, "text": c.text[:300], "issues": c.issues,
                   "missing": c.missing} for c in v.checks if c.issues]
        grouped: dict[str, int] = defaultdict(int)
        for c in v.checks:
            for i in c.issues:
                grouped[i.split(":")[0]] += 1
        return {"report_id": report_id, "ok": v.ok, "summary": v.summary(),
                "issue_counts": dict(grouped), "issues": issues[:40],
                "next": "done" if v.ok else "fix the listed sentences (cite, soften, or remove) "
                                             f"and call write_report with supersedes_id={report_id}"}

    def confirm_cross_link(self, link_id: int, explanation: str, evidence_ids: list[int],
                           premises: list[dict] | None = None, confidence: float = 0.7) -> dict:
        """Confirm a cross-investigation link, with evidence from both sides."""
        if not evidence_ids:
            raise ToolError("confirming a link needs evidence_ids (ideally from both "
                            "investigations)")
        try:
            prem = [(PremiseType(p["type"]), int(p["id"])) for p in premises or []]
        except (ValueError, KeyError, TypeError) as e:
            raise ToolError(f"bad premise: {e}") from e
        try:
            with self.session_factory() as s, s.begin():
                c = s.get(CrossLink, link_id)
                if c is None or self.investigation_id not in (c.investigation_a,
                                                              c.investigation_b):
                    raise ToolError(f"no cross link {link_id} involving this investigation")
                sources = s.scalars(select(EvidenceLink).where(
                    EvidenceLink.id.in_(evidence_ids))).all()
                missing = set(evidence_ids) - {e.id for e in sources}
                if missing:
                    raise ToolError(f"unknown evidence ids {sorted(missing)}")
                for src in sources:
                    s.add(EvidenceLink(
                        target_type="cross_link", target_id=c.id, artifact_id=src.artifact_id,
                        document_id=src.document_id, quote_original=src.quote_original,
                        quote_translated=src.quote_translated, char_start=src.char_start,
                        char_end=src.char_end, media_locator=src.media_locator,
                        quote_verified=src.quote_verified, verified_at=src.verified_at,
                        created_by=f"{self.actor} via E:{src.id}"))
                inf = Inference(conclusion_type="cross_link", conclusion_id=c.id,
                                method=f"link analysis ({c.tier} via {c.via_type} {c.via_id})",
                                rationale=explanation, confidence=confidence,
                                created_by=self.actor)
                s.add(inf)
                s.flush()
                keys = {(p.value, i) for p, i in prem} | {("evidence", e.id) for e in sources}
                for ptype, pid in keys:
                    s.add(InferencePremise(inference_id=inf.id, premise_type=ptype,
                                           premise_id=pid))
                c.status, c.explanation, c.decided_by = "confirmed", explanation, self.actor
                if c.tier == "soft":
                    c.tier = "analytic"
        except DBAPIError as e:
            raise ToolError(f"rejected by integrity rules: {str(e.orig).splitlines()[0]}") from e
        return {"link_id": link_id, "status": "confirmed"}

    def reject_cross_link(self, link_id: int, reason: str) -> dict:
        """Reject a candidate link (e.g. a generic place shared by unrelated cases)."""
        with self.session_factory() as s, s.begin():
            c = s.get(CrossLink, link_id)
            if c is None or self.investigation_id not in (c.investigation_a, c.investigation_b):
                raise ToolError(f"no cross link {link_id} involving this investigation")
            c.status, c.explanation, c.decided_by = "rejected", reason, self.actor
        return {"link_id": link_id, "status": "rejected"}

    def propose_finding_revision(self, finding_id: int, new_confidence: float, reason: str,
                                 evidence_ids: list[int] | None = None,
                                 withdraw: bool = False) -> dict:
        """Lower/raise a finding's confidence or withdraw it, with reason and evidence."""
        from osint.analyst.revisions import RevisionError, propose_revision

        try:
            with self.session_factory() as s, s.begin():
                return propose_revision(s, finding_id, new_confidence, reason, self.actor,
                                        evidence_ids, withdraw, self.auto_apply_downgrades,
                                        investigation_id=self.investigation_id)
        except RevisionError as e:
            raise ToolError(str(e)) from e
