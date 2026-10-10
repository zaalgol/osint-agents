"""Domain enrichment: RDAP registration data + DNS records (no key, no account).

RDAP (the structured successor of WHOIS) via rdap.org, which redirects to the
authoritative registry, is captured with proof. DNS answers come from the system
resolver and are recorded as an observation at a stated time.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import ClassVar

from osint.core.context import PluginContext
from osint.core.models import EntityRef, ExtractedEntity, ExtractedRelation, ExtractionResult
from osint.core.plugins import Enricher
from osint.enrichment.base import EnrichmentResult, EntityView
from osint.evidence.capture import capture_url
from osint.resolution.normalize import domain_key

REDACTED = ("redacted", "privacy", "data protected", "not disclosed", "withheld")


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] in ("fn", "org") and item[3]:
            return str(item[3]).strip()
    return None


def _dns(domain: str) -> dict[str, list[str]]:
    import dns.exception
    import dns.resolver

    out: dict[str, list[str]] = {}
    r = dns.resolver.Resolver()
    r.lifetime = 8
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            out[rtype] = sorted(str(x).strip('"') for x in r.resolve(domain, rtype))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            pass  # no records of this type is an answer too
    return out


class RdapEnricher(Enricher):
    name = "rdap"
    version = "0.1.0"
    description = "Domain registration (RDAP) and DNS records."
    entity_types: ClassVar[set[str]] = {"domain", "url", "email"}

    async def enrich(self, entity: EntityView, ctx: PluginContext) -> EnrichmentResult:
        source = entity.strong_key or entity.name
        domain = domain_key(source.split("@")[-1]) if "@" in source else domain_key(source)
        if not domain:
            return EnrichmentResult(skipped=f"no domain in {source!r}")
        item = await capture_url(ctx, f"https://rdap.org/domain/{domain}", self.ident,
                                 screenshot=False, platform="rdap")
        item.parse = False
        res = EnrichmentResult(captures=[item])
        lines = [f"Domain: {domain}"]
        attrs: dict = {"domain": domain}
        registrar = None
        if item.meta.http_status == 200:
            import json

            data = json.loads(item.data)
            for ev in data.get("events", []):
                action, date = ev.get("eventAction"), (ev.get("eventDate") or "")[:10]
                if action in ("registration", "expiration", "last changed") and date:
                    lines.append(f"{action.capitalize()}: {date}")
                    attrs[action.replace(" ", "_")] = date
            for ent in data.get("entities", []):
                roles = ent.get("roles") or []
                name = _vcard_name(ent)
                if not name:
                    continue
                if "registrar" in roles:
                    registrar = name
                    lines.append(f"Registrar: {name}")
                    attrs["registrar"] = name
                elif "registrant" in roles and not any(r in name.lower() for r in REDACTED):
                    lines.append(f"Registrant: {name}")
                    attrs["registrant"] = name
            ns = sorted({(n.get("ldhName") or "").lower() for n in data.get("nameservers", [])} - {""})
            if ns:
                lines.append(f"Nameservers: {', '.join(ns)}")
                attrs["nameservers"] = ns
            if data.get("status"):
                lines.append(f"Status: {', '.join(data['status'])}")
        else:
            lines.append(f"RDAP lookup returned HTTP {item.meta.http_status}")
        records = await asyncio.to_thread(_dns, domain)
        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        for rtype, vals in records.items():
            lines.append(f"DNS {rtype} ({stamp}): {', '.join(vals)}")
        attrs["dns"] = records
        res.facts_text = "\n".join(lines)
        ents = [ExtractedEntity(name=domain, type="domain", quote=f"Domain: {domain}")]
        rels = []
        if registrar:
            ents.append(ExtractedEntity(name=registrar, type="organization",
                                        quote=f"Registrar: {registrar}"))
            rels.append(ExtractedRelation(type="registered_by",
                                          src=EntityRef(name=domain, type="domain"),
                                          dst=EntityRef(name=registrar, type="organization"),
                                          quote=f"Registrar: {registrar}", confidence=0.95))
        for ip in records.get("A", []) + records.get("AAAA", []):
            line = next(ln for ln in lines if ip in ln and ln.startswith("DNS A"))
            ents.append(ExtractedEntity(name=ip, type="ip_address", quote=ip))
            rels.append(ExtractedRelation(type="resolves_to",
                                          src=EntityRef(name=domain, type="domain"),
                                          dst=EntityRef(name=ip, type="ip_address"),
                                          quote=line, confidence=0.9))
        res.extraction = ExtractionResult(entities=ents, relations=rels)
        res.attributes = attrs
        return res
