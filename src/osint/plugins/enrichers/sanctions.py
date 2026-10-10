"""Sanctions/terror-designation screening: UN Security Council Consolidated List + US OFAC SDN.

The lists are public (no key) and captured with proof at most once per day, then reused.
Matching uses transliterated, normalized names plus aliases (exact key, or fuzzy
>= 92).

Policy, to avoid false accusations:
  * organizations/groups: a match becomes a `designated_by` relation citing the
    verbatim list entry (confidence by match quality)
  * people: a name match alone is NOT a fact; it becomes a `sanctions_match` review item
    with the entry text, for an analyst to confirm (dates of birth, nationality, ...)
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import ClassVar
from xml.etree import ElementTree as ET

from rapidfuzz import fuzz
from sqlalchemy import select

from osint.core.context import PluginContext
from osint.core.models import EntityRef, ExtractedEntity, ExtractedRelation, ExtractionResult
from osint.core.plugins import Enricher
from osint.enrichment.base import EnrichmentResult, EntityView
from osint.evidence.capture import capture_url
from osint.resolution.er import ascii_key

LISTS = {
    "un": ("https://scsanctions.un.org/resources/xml/en/consolidated.xml",
           "UN Security Council"),
    "ofac_sdn": ("https://www.treasury.gov/ofac/downloads/sdn.csv", "US Treasury OFAC"),
    "ofac_alt": ("https://www.treasury.gov/ofac/downloads/alt.csv", None),
}
MAX_AGE = timedelta(hours=24)
FUZZY = 92


@dataclass
class ListEntry:
    source: str
    authority: str
    ref: str
    kind: str                     # individual | entity
    names: list[str]
    line: str                     # verbatim summary used for citations
    keys: set[str] = field(default_factory=set)


def _txt(el, tag: str) -> str:
    x = el.find(tag)
    return (x.text or "").strip() if x is not None and x.text else ""


def parse_un(xml_bytes: bytes) -> list[ListEntry]:
    root = ET.fromstring(xml_bytes)
    out = []
    for kind, path, alias_tag in (("individual", "INDIVIDUALS/INDIVIDUAL", "INDIVIDUAL_ALIAS"),
                                  ("entity", "ENTITIES/ENTITY", "ENTITY_ALIAS")):
        for el in root.findall(path):
            name = " ".join(p for p in (_txt(el, "FIRST_NAME"), _txt(el, "SECOND_NAME"),
                                        _txt(el, "THIRD_NAME"), _txt(el, "FOURTH_NAME")) if p)
            aliases = [_txt(a, "ALIAS_NAME") for a in el.findall(alias_tag) if _txt(a, "ALIAS_NAME")]
            ref = _txt(el, "REFERENCE_NUMBER")
            line = (f"UN Security Council Consolidated List {ref} ({_txt(el, 'UN_LIST_TYPE')}): "
                    f"{name}" + (f"; aliases: {'; '.join(aliases[:12])}" if aliases else "")
                    + f"; listed on {_txt(el, 'LISTED_ON')}")
            out.append(ListEntry("un", "UN Security Council", ref, kind, [name, *aliases], line))
    return out


def parse_ofac(sdn_csv: bytes, alt_csv: bytes | None) -> list[ListEntry]:
    def rows(b: bytes):
        return csv.reader(io.StringIO(b.decode("utf-8", "replace")))

    alts: dict[str, list[str]] = {}
    for r in rows(alt_csv or b""):
        if len(r) >= 4 and r[3].strip() not in ("", "-0-"):
            alts.setdefault(r[0].strip(), []).append(r[3].strip())
    out = []
    for r in rows(sdn_csv):
        if len(r) < 4 or not r[0].strip().isdigit():
            continue
        num, name, typ, program = (x.strip() for x in r[:4])
        kind = "individual" if typ.lower() == "individual" else "entity"
        aliases = alts.get(num, [])
        line = (f"OFAC SDN entry {num} [{program}]: {name}"
                + (f"; a.k.a. {'; '.join(aliases[:12])}" if aliases else ""))
        out.append(ListEntry("ofac", "US Treasury OFAC", num, kind, [name, *aliases], line))
    return out


ARTICLES = {"the", "al", "el", "ul"}   # "THE HOUTHIS" = "Houthis"; "AL-HUTHI" = "Huthi"


def _keys(names: list[str]) -> set[str]:
    out = set()
    for n in names:
        # OFAC writes "LAST, First": index both orders
        for variant in (n, " ".join(reversed([p.strip() for p in n.split(",", 1)]))):
            k = ascii_key(variant)
            bare = " ".join(t for t in k.split() if t not in ARTICLES)
            for key in (k, bare):
                if len(key) >= 4:
                    out.add(key)
    return out


class SanctionsEnricher(Enricher):
    name = "sanctions"
    version = "0.1.0"
    description = "Screen people/organizations against UN and OFAC sanctions lists."
    entity_types: ClassVar[set[str]] = {"person", "organization", "armed_group"}
    _cache: ClassVar[dict] = {}          # per process: (date) -> (entries, captures)

    async def _lists(self, ctx: PluginContext):
        from osint.storage.db import Artifact

        today = datetime.now(UTC).date().isoformat()
        if self._cache.get("date") == today:
            return self._cache["entries"], []
        raw: dict[str, bytes] = {}
        new_captures = []
        with ctx.session() as s:
            for key in LISTS:
                art = s.scalar(select(Artifact).where(
                    Artifact.platform_id == f"sanctions:{key}",
                    Artifact.fetched_at_utc >= datetime.now(UTC) - MAX_AGE)
                    .order_by(Artifact.id.desc()).limit(1))
                if art is not None and ctx.raw_store.exists(art.sha256):
                    raw[key] = ctx.raw_store.read_bytes(art.sha256)  # else: purged -> refetch
        for key, (url, _) in LISTS.items():
            if key in raw:
                continue
            item = await capture_url(ctx, url, self.ident, screenshot=False, platform="sanctions")
            item.parse = False
            item.meta.platform_id = f"sanctions:{key}"
            new_captures.append(item)
            if item.meta.http_status == 200:
                raw[key] = item.data
        entries = []
        if raw.get("un"):
            entries += parse_un(raw["un"])
        if raw.get("ofac_sdn"):
            entries += parse_ofac(raw["ofac_sdn"], raw.get("ofac_alt"))
        owners: dict[str, set[str]] = {}
        for e in entries:
            e.keys = _keys(e.names)
            for k in e.keys:
                owners.setdefault(k, set()).add(f"{e.source}:{e.ref}")
        SanctionsEnricher._cache = {"date": today, "entries": entries, "owners": owners}
        return entries, new_captures

    async def enrich(self, entity: EntityView, ctx: PluginContext) -> EnrichmentResult:
        entries, captures = await self._lists(ctx)
        res = EnrichmentResult(captures=captures)
        mine = _keys([entity.name, *entity.aliases])
        want = "individual" if entity.type == "person" else "entity"
        hits = []
        for e in entries:
            if e.kind != want:
                continue
            shared = mine & e.keys
            if shared:
                hits.append((e, 1.0, shared))
                continue
            best = max((fuzz.token_sort_ratio(a, b) for a in mine for b in e.keys
                        if abs(len(a.split()) - len(b.split())) <= 1), default=0)
            if best >= FUZZY:
                hits.append((e, best / 100, set()))
        if not hits:
            res.attributes = {"screened": [k for k in ("un", "ofac")], "matches": 0}
            return res
        hits.sort(key=lambda h: -h[1])
        hits = hits[:5]
        lines = [f"Sanctions screening for: {entity.name} ({entity.type})"]
        lines += [h[0].line for h in hits]
        res.facts_text = "\n".join(lines)
        owners = self._cache.get("owners", {})
        res.attributes = {"matches": len(hits),
                          "entries": [{"list": e.source, "ref": e.ref, "score": round(sc, 2)}
                                      for e, sc, _ in hits]}
        if entity.type == "person":
            for e, sc, _ in hits:
                res.reviews.append({
                    "kind": "sanctions_match",
                    "reason": f"possible {e.authority} listing ({e.ref}, name score {sc:.2f}); "
                              "confirm with identifiers before treating as fact",
                    "list_entry": e.line})
            return res
        ents = [ExtractedEntity(name=entity.name, type=entity.type, quote=entity.name)] \
            if entity.name in res.facts_text else []
        rels = []
        for e, sc, keys in hits:
            # Only an unambiguous, specific name becomes a fact. Ambiguous means the
            # matched name is shared by several listed parties (e.g. "Ansar Allah" is
            # also an alias of Hizballah); generic means a single word ("Vanguard").
            ambiguous = any(len(owners.get(k, ())) > 1 for k in keys) or (not keys and sc < 1.0)
            generic = len(entity.name.split()) < 2 and not entity.aliases[1:]
            if ambiguous or generic:
                why = "name shared by several listed parties" if ambiguous else "generic name"
                res.reviews.append({
                    "kind": "sanctions_match",
                    "reason": f"possible {e.authority} listing ({e.ref}); {why}: confirm "
                              "it is the same party before treating as fact",
                    "list_entry": e.line})
                continue
            ents.append(ExtractedEntity(name=e.authority, type="organization", quote=e.authority)
                        if e.authority in res.facts_text else
                        ExtractedEntity(name=e.authority, type="organization", quote=e.line))
            rels.append(ExtractedRelation(
                type="designated_by", src=EntityRef(name=entity.name, type=entity.type),
                dst=EntityRef(name=e.authority, type="organization"), quote=e.line,
                confidence=0.9 if sc == 1.0 else 0.7))
        res.extraction = ExtractionResult(entities=ents, relations=rels)
        return res
