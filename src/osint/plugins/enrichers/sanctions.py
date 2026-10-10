"""Sanctions/terror-designation screening: UN Security Council Consolidated List, US OFAC
SDN, the EU consolidated financial sanctions list and the UK Sanctions List (FCDO).

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
import logging
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

OFAC = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports"
LISTS = {
    "un": ("https://scsanctions.un.org/resources/xml/en/consolidated.xml",
           "UN Security Council"),
    "ofac_sdn": (f"{OFAC}/SDN.CSV", "US Treasury OFAC"),
    "ofac_alt": (f"{OFAC}/ALT.CSV", None),
    # the token is the public one the Commission publishes for this file
    "eu": (("https://webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content"
           "?token=dG9rZW4tMjAxNw"), "Council of the European Union"),
    "uk": ("https://sanctionslist.fcdo.gov.uk/docs/UK-Sanctions-List.csv", "UK Government (FCDO)"),
}
SCREENED = ("un", "ofac", "eu", "uk")
MAX_AGE = timedelta(hours=24)
log = logging.getLogger(__name__)
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


def parse_eu(xml_bytes: bytes) -> list[ListEntry]:
    """EU Financial Sanctions Files export (namespaced XML, one sanctionEntity per party)."""
    root = ET.fromstring(xml_bytes)
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    out = []
    for el in root.iter(f"{ns}sanctionEntity"):
        st = el.find(f"{ns}subjectType")
        code = st.get("code") if st is not None else ""
        if code not in ("person", "enterprise"):
            continue
        ranked = []                       # English first, then other Latin-script names
        for a in el.findall(f"{ns}nameAlias"):
            n = (a.get("wholeName") or "").strip()
            if n:
                english = (a.get("nameLanguage") or a.get("regulationLanguage") or "").lower() == "en"
                ranked.append((0 if english else 1 if n.isascii() else 2, n))
        names = []
        for _, n in sorted(ranked, key=lambda x: x[0]):
            if n not in names:
                names.append(n)
        if not names:
            continue
        ref = el.get("euReferenceNumber") or el.get("logicalId") or ""
        reg = el.find(f"{ns}regulation")
        programme = reg.get("programme", "") if reg is not None else ""
        since = reg.get("entryIntoForceDate", "") if reg is not None else ""
        line = (f"EU consolidated financial sanctions list {ref} [{programme}]: {names[0]}"
                + (f"; aliases: {'; '.join(names[1:13])}" if len(names) > 1 else "")
                + (f"; in force since {since}" if since else ""))
        out.append(ListEntry("eu", "Council of the European Union", ref,
                             "individual" if code == "person" else "entity", names, line))
    return out


def parse_uk(csv_bytes: bytes) -> list[ListEntry]:
    """UK Sanctions List CSV: a report-date line, a header, then one row per name variant."""
    lines = csv_bytes.decode("utf-8-sig", "replace").splitlines()
    start = next((i for i, ln in enumerate(lines[:5]) if "Unique ID" in ln), None)
    if start is None:
        return []
    groups: dict[str, dict] = {}
    for r in csv.DictReader(io.StringIO("\n".join(lines[start:]))):
        uid = (r.get("Unique ID") or "").strip()
        typ = (r.get("Designation Type") or "").strip().lower()
        if not uid or typ not in ("individual", "entity"):
            continue                      # ships are screened elsewhere (by IMO number)
        name = " ".join(p.strip() for p in (r.get(f"Name {i}") or "" for i in (1, 2, 3, 4, 5, 6))
                        if p.strip())
        g = groups.setdefault(uid, {"kind": typ, "primary": [], "names": [],
                                    "regime": (r.get("Regime Name") or "").strip(),
                                    "since": (r.get("Date Designated") or "").strip()})
        if name and name not in g["names"]:
            g["names"].append(name)
            if (r.get("Name type") or "").strip().lower() == "primary name":
                g["primary"].append(name)
    out = []
    for uid, g in groups.items():
        if not g["names"]:
            continue
        names = g["primary"][:1] + [n for n in g["names"] if n not in g["primary"][:1]]
        line = (f"UK Sanctions List {uid} [{g['regime']}]: {names[0]}"
                + (f"; aliases: {'; '.join(names[1:13])}" if len(names) > 1 else "")
                + (f"; designated {g['since']}" if g["since"] else ""))
        out.append(ListEntry("uk", "UK Government (FCDO)", uid, g["kind"], names, line))
    return out


APOSTROPHES = dict.fromkeys(map(ord, [chr(39), chr(0x2019), chr(0x2018), chr(96), chr(0x02BC)]))
ARTICLES = {"the", "al", "el", "ul"}   # "THE HOUTHIS" = "Houthis"; "AL-HUTHI" = "Huthi"


def _keys(names: list[str]) -> set[str]:
    out = set()
    for n in names:
        # OFAC writes "LAST, First": index both orders
        for variant in (n, " ".join(reversed([p.strip() for p in n.split(",", 1)]))):
            # "KATA'IB" = "Kataib": drop apostrophes (ASCII, typographic, backtick)
            k = ascii_key(variant.translate(APOSTROPHES))
            bare = " ".join(t for t in k.split() if t not in ARTICLES)
            for key in (k, bare):
                if len(key) >= 4:
                    out.add(key)
    return out


def _parties(owner_ids, matched: set[str]) -> int:
    """How many distinct parties own a matched name. Entries are the same party when they
    share another name, or when the matched name is the primary name on both lists
    ("HIZBALLAH" on OFAC and the UK list). A name that is only an alias on each needs
    corroboration: "Ansar Allah" is an alias of both the Houthis and Hizballah."""
    by_id = SanctionsEnricher._cache.get("by_id", {})

    def primary(e: ListEntry) -> set[str]:
        return _keys(e.names[:1]) & matched

    def same(a: ListEntry, b: ListEntry) -> bool:
        return bool((a.keys & b.keys) - matched) or bool(primary(a) & primary(b))

    groups: list[list[ListEntry]] = []
    for e in (by_id[i] for i in owner_ids if i in by_id):
        joined = [g for g in groups if any(same(e, o) for o in g)]
        groups = [g for g in groups if g not in joined] + [[e, *(o for g in joined for o in g)]]
    return len(groups)


class SanctionsEnricher(Enricher):
    name = "sanctions"
    version = "0.1.0"
    description = "Screen people/organizations against UN, OFAC, EU and UK sanctions lists."
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
        for key, parse in (("eu", parse_eu), ("uk", parse_uk)):
            if raw.get(key):
                try:
                    entries += parse(raw[key])
                except (ET.ParseError, csv.Error, ValueError) as e:   # one bad list != no screening
                    log.warning("sanctions list %s unparseable: %s", key, e)
        owners: dict[str, set[str]] = {}
        for e in entries:
            e.keys = _keys(e.names)
            for k in e.keys:
                owners.setdefault(k, set()).add(f"{e.source}:{e.ref}")
        SanctionsEnricher._cache = {"date": today, "entries": entries, "owners": owners,
                                    "by_id": {f"{e.source}:{e.ref}": e for e in entries}}
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
            res.attributes = {"screened": list(SCREENED), "matches": 0}
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
                    "list_entry": e.line, "authority": e.authority})
            return res
        ents = [ExtractedEntity(name=entity.name, type=entity.type, quote=entity.name)] \
            if entity.name in res.facts_text else []
        rels = []
        for e, sc, keys in hits:
            # Only an unambiguous, specific name becomes a fact. Ambiguous means the
            # matched name is shared by several listed parties (e.g. "Ansar Allah" is
            # also an alias of Hizballah); generic means a single word ("Vanguard").
            # Entries on several lists are the same party when they also share another name
            # (the Houthis on the OFAC, EU and UK lists); otherwise they are different parties.
            ambiguous = any(_parties(owners.get(k, ()), keys) > 1
                            for k in keys) or (not keys and sc < 1.0)
            generic = len(entity.name.split()) < 2 and not entity.aliases[1:]
            # Matching only one of the entry's aliases is weak ("ISLAMIC JIHAD" is an alias
            # of Hizballah and the name of other groups): it needs the primary name or a
            # second matching name.
            own = {n for n in [entity.name, *entity.aliases] if _keys([n]) & e.keys}
            alias_only = bool(keys) and not (_keys(e.names[:1]) & keys) and len(own) < 2
            if ambiguous or generic or alias_only:
                why = ("name shared by several listed parties" if ambiguous else
                       "generic name" if generic else "matched only an alias")
                res.reviews.append({
                    "kind": "sanctions_match",
                    "reason": f"possible {e.authority} listing ({e.ref}); {why}: confirm "
                              "it is the same party before treating as fact",
                    "list_entry": e.line, "authority": e.authority})
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
