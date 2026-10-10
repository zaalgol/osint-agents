"""Exporters: STIX 2.1 (threat intel), FollowTheMoney (Aleph/OpenSanctions), GEXF (Gephi).

Every exported fact keeps its provenance: STIX relationships carry x_osint_evidence
(verbatim quote, source URL, capture time, SHA-256), and FtM entities carry sourceUrl
and the quotes as notes. IDs are deterministic (UUIDv5 of the database id), so
re-exports line up with earlier ones.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.core.context import PluginContext
from osint.core.plugins import Exporter
from osint.storage.db import (
    Artifact,
    CitationRetraction,
    Entity,
    EntityAlias,
    Event,
    EventParticipant,
    EvidenceLink,
    Finding,
    Investigation,
    InvestigationRef,
    Relation,
    SupportStats,
)

NS = uuid.UUID("6f0c6a8e-7b8e-4d1f-9a43-0e5b7c4d2a11")


def sid(kind: str, pg_id: int | str) -> str:
    return f"{kind}--{uuid.uuid5(NS, f'{kind}:{pg_id}')}"


def ts(dt: datetime | None) -> str:
    return (dt or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Scope:
    """Everything one investigation references, loaded once."""

    def __init__(self, s: Session, inv_id: int):
        self.s = s
        self.inv = s.get(Investigation, inv_id)

        def refs(t):
            return select(InvestigationRef.object_id).where(
                InvestigationRef.investigation_id == inv_id, InvestigationRef.object_type == t)

        self.entities = s.scalars(select(Entity).where(Entity.id.in_(refs("entity")),
                                                       Entity.merged_into_id.is_(None))).all()
        live = {e.id for e in self.entities}
        self.relations = [r for r in s.scalars(select(Relation).where(
                              Relation.id.in_(refs("relation")),
                              Relation.attributes["retracted"].is_(None)))
                          if r.src_entity_id in live and r.dst_entity_id in live]
        self.events = s.scalars(select(Event).where(Event.id.in_(refs("event")))).all()
        self.participants = s.execute(select(EventParticipant).where(
            EventParticipant.event_id.in_([e.id for e in self.events]))).scalars().all()
        self.findings = s.scalars(select(Finding).where(Finding.investigation_id == inv_id)).all()

    def aliases(self, eid: int) -> list[str]:
        return sorted(set(self.s.scalars(select(EntityAlias.alias).where(EntityAlias.entity_id == eid))))

    def evidence(self, target_type: str, target_id: int, limit: int = 5) -> list[dict]:
        rows = self.s.execute(select(EvidenceLink, Artifact).join(
            Artifact, Artifact.id == EvidenceLink.artifact_id).where(
            EvidenceLink.target_type == target_type, EvidenceLink.target_id == target_id,
            EvidenceLink.id.not_in(select(CitationRetraction.evidence_link_id))).limit(limit))
        return [{"evidence_id": ev.id, "quote": ev.quote_original,
                 "url": art.final_url or art.url, "captured": ts(art.fetched_at_utc),
                 "sha256": art.sha256} for ev, art in rows]

    def sources(self, target_type: str, target_id: int) -> int | None:
        st = self.s.get(SupportStats, (target_type, target_id))
        return st.independent_sources if st else None


# --------------------------------------------------------------------------- STIX 2.1

SCO = {"domain": "domain-name", "url": "url", "email": "email-addr", "ip_address": "ipv4-addr"}


def to_stix(scope: Scope) -> dict:
    now = ts(None)
    me = {"type": "identity", "spec_version": "2.1", "id": sid("identity", "osint-agents"),
          "created": now, "modified": now, "name": "osint-agents", "identity_class": "system"}
    objs: list[dict] = [me]
    ids: dict[int, str] = {}

    def sdo(kind: str, pg_id, **props) -> dict:
        o = {"type": kind, "spec_version": "2.1", "id": sid(kind, pg_id), "created": now,
             "modified": now, "created_by_ref": me["id"], **props}
        objs.append(o)
        return o

    for e in scope.entities:
        aliases = [a for a in scope.aliases(e.id) if a != e.canonical_name]
        if e.type in SCO:
            kind = SCO[e.type]
            if e.type == "ip_address" and ":" in (e.strong_key or e.canonical_name):
                kind = "ipv6-addr"
            value = e.strong_key or e.canonical_name
            o = {"type": kind, "spec_version": "2.1", "id": sid(kind, e.id), "value": value}
            objs.append(o)
        elif e.type == "person":
            o = sdo("identity", e.id, name=e.canonical_name, identity_class="individual",
                    **({"x_osint_aliases": aliases} if aliases else {}))
        elif e.type in ("armed_group",):
            o = sdo("threat-actor", e.id, name=e.canonical_name, threat_actor_types=["terrorist"],
                    **({"aliases": aliases} if aliases else {}))
        elif e.type == "organization":
            o = sdo("identity", e.id, name=e.canonical_name, identity_class="organization",
                    **({"x_osint_aliases": aliases} if aliases else {}))
        elif e.type == "location":
            geo = (e.attributes or {}).get("geocode") or {}
            extra = {"latitude": geo["lat"], "longitude": geo["lon"]} if "lat" in geo else {}
            o = sdo("location", e.id, name=e.canonical_name,
                    **(extra or {"region": "unknown"}))
        elif e.type in ("online_account", "channel"):
            o = {"type": "user-account", "spec_version": "2.1", "id": sid("user-account", e.id),
                 "account_login": e.canonical_name, "display_name": e.canonical_name}
            objs.append(o)
        else:
            o = sdo("x-osint-entity", e.id, name=e.canonical_name, x_osint_type=e.type)
        ids[e.id] = o["id"]

    for r in scope.relations:
        ev = scope.evidence("relation", r.id)
        sdo("relationship", f"rel{r.id}", relationship_type=r.type.replace("_", "-"),
            source_ref=ids[r.src_entity_id], target_ref=ids[r.dst_entity_id],
            confidence=round(r.confidence * 100),
            x_osint_evidence=ev, x_osint_independent_sources=scope.sources("relation", r.id))

    for v in scope.events:
        inc = sdo("incident", v.id, name=f"{v.type}: {v.description[:120]}",
                  description=v.description, x_osint_event_type=v.type,
                  x_osint_time=ts(v.time) if v.time else None,
                  x_osint_time_precision=v.time_precision,
                  x_osint_evidence=scope.evidence("event", v.id))
        if v.location_entity_id in ids:
            sdo("relationship", f"loc{v.id}", relationship_type="located-at",
                source_ref=inc["id"], target_ref=ids[v.location_entity_id])
        for p in scope.participants:
            if p.event_id == v.id and p.entity_id in ids:
                sdo("relationship", f"part{v.id}-{p.entity_id}-{p.role}",
                    relationship_type="x-osint-" + p.role.replace(":", "-").replace("_", "-"),
                    source_ref=ids[p.entity_id], target_ref=inc["id"])

    for f in scope.findings:
        sdo("note", f"finding{f.id}", abstract=f"{f.kind} ({f.epistemic_status})",
            content=f.text, object_refs=[me["id"]],
            x_osint_confidence=f.confidence, x_osint_epistemic_status=f.epistemic_status,
            x_osint_evidence=scope.evidence("finding", f.id))

    sdo("report", f"inv{scope.inv.id}", name=f"OSINT investigation: {scope.inv.name}",
        report_types=["threat-report"], published=now,
        object_refs=[o["id"] for o in objs if o["id"] != me["id"]] or [me["id"]],
        description=(scope.inv.seed or {}).get("focus") or scope.inv.name)
    return {"type": "bundle", "id": sid("bundle", f"inv{scope.inv.id}-{now}"), "objects": objs}


# --------------------------------------------------------------------------- FollowTheMoney

FTM_SCHEMA = {"person": "Person", "organization": "Organization", "armed_group": "Organization",
              "location": "Address", "online_account": "UserAccount", "channel": "UserAccount",
              "crypto_wallet": "CryptoWallet", "vehicle": "Vehicle", "document": "Document"}


def to_ftm(scope: Scope) -> list[dict]:
    out, ids = [], {}
    for e in scope.entities:
        schema = FTM_SCHEMA.get(e.type)
        if schema is None:
            continue
        fid = f"osint-{e.id}"
        props: dict[str, list[Any]] = {"name": [e.canonical_name]}
        aliases = [a for a in scope.aliases(e.id) if a != e.canonical_name]
        if aliases:
            props["alias"] = aliases
        if schema == "Address":
            props = {"full": [e.canonical_name]}
            geo = (e.attributes or {}).get("geocode") or {}
            if "lat" in geo:
                props |= {"latitude": [str(geo["lat"])], "longitude": [str(geo["lon"])]}
        if schema == "CryptoWallet":
            props = {"publicKey": [e.strong_key or e.canonical_name]}
        if schema == "UserAccount":
            props = {"username": [e.canonical_name]}
        if e.type == "armed_group":
            props["topics"] = ["crime.terror"]
        out.append({"id": fid, "schema": schema, "properties": props})
        ids[e.id] = (fid, schema)

    def link(r: Relation) -> dict | None:
        (a, sa), (b, _sb) = ids.get(r.src_entity_id, (None, None)), ids.get(r.dst_entity_id, (None, None))
        if not a or not b:
            return None
        ev = scope.evidence("relation", r.id, 3)
        notes = [f"“{x['quote']}” ({x['url']}, {x['captured']}, sha256 {x['sha256']})" for x in ev]
        base = {"id": f"osint-rel-{r.id}"}
        src_urls = [x["url"] for x in ev if x["url"]]
        if r.type in ("member_of", "leader_of") and sa in ("Person", "Organization"):
            props = {"member": [a], "organization": [b], "role": [r.type.replace("_", " ")]}
            return {**base, "schema": "Membership", "properties": props | {"sourceUrl": src_urls, "description": notes}}
        if r.type == "funds":
            return {**base, "schema": "Payment", "properties": {"payer": [a], "beneficiary": [b], "sourceUrl": src_urls, "description": notes}}
        return {**base, "schema": "UnknownLink", "properties": {
            "subject": [a], "object": [b], "role": [r.type.replace("_", " ")],
            "sourceUrl": src_urls, "description": notes}}

    out += [x for r in scope.relations if (x := link(r))]
    for v in scope.events:
        involved = [ids[p.entity_id][0] for p in scope.participants
                    if p.event_id == v.id and p.entity_id in ids]
        props = {"name": [f"{v.type}: {v.description[:200]}"], "summary": [v.description]}
        if v.time:
            props["date"] = [v.time.date().isoformat()]
        if involved:
            props["involved"] = involved
        out.append({"id": f"osint-event-{v.id}", "schema": "Event", "properties": props})
    return out


# --------------------------------------------------------------------------- plugins


class _FileExporter(Exporter):
    suffix: ClassVar[str] = ""

    async def export(self, scope: Any, out: Path, ctx: PluginContext) -> Path:
        return self.write(scope, out)

    def write(self, scope: Scope, out: Path) -> Path:
        raise NotImplementedError


class StixExporter(_FileExporter):
    name = "stix"
    description = "STIX 2.1 bundle (threat intel), evidence on every relationship."
    formats: ClassVar[set[str]] = {"stix"}
    suffix = ".stix.json"

    def write(self, scope: Scope, out: Path) -> Path:
        out.write_text(json.dumps(to_stix(scope), indent=1, ensure_ascii=False), encoding="utf-8")
        return out


class FtmExporter(_FileExporter):
    name = "ftm"
    description = "FollowTheMoney entities (JSON lines) for Aleph / OpenSanctions tooling."
    formats: ClassVar[set[str]] = {"ftm"}
    suffix = ".ftm.jsonl"

    def write(self, scope: Scope, out: Path) -> Path:
        with open(out, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(e, ensure_ascii=False) + "\n" for e in to_ftm(scope))
        return out


class GexfExporter(_FileExporter):
    name = "gexf"
    description = "GEXF network for Gephi (entities, relations, shared events)."
    formats: ClassVar[set[str]] = {"gexf"}
    suffix = ".gexf"

    def write(self, scope: Scope, out: Path) -> Path:
        import networkx as nx

        from osint.linking.network import build_graph

        g = build_graph(scope.s, scope.inv.id)
        nx.write_gexf(g, out)
        return out
