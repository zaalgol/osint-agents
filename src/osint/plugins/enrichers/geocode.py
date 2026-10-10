"""Geocode locations with OpenStreetMap Nominatim (no key, no account).

Nominatim's usage policy applies: at most one request per second with an identifying
User-Agent. The top candidate's coordinates are stored as a *candidate* (place names are
ambiguous), along with the alternatives, so an analyst or Claude can tell e.g. Mokha
(Yemen) from Mocha (Chile).
"""

from __future__ import annotations

import json
from typing import ClassVar

from osint.core.context import PluginContext
from osint.core.plugins import Enricher
from osint.enrichment.base import EnrichmentResult, EntityView
from osint.evidence.capture import capture_url

API = "https://nominatim.openstreetmap.org/search"


class GeocodeEnricher(Enricher):
    name = "geocode"
    version = "0.1.0"
    description = "OpenStreetMap Nominatim geocoding (candidate coordinates)."
    entity_types: ClassVar[set[str]] = {"location"}

    async def enrich(self, entity: EntityView, ctx: PluginContext) -> EnrichmentResult:
        item = await capture_url(ctx, API, self.ident, screenshot=False, platform="nominatim",
                                 params={"q": entity.name, "format": "jsonv2", "limit": 5,
                                         "accept-language": "en", "addressdetails": 1})
        item.parse = False
        res = EnrichmentResult(captures=[item])
        try:
            hits = json.loads(item.data) if item.meta.http_status == 200 else []
        except ValueError:
            hits = []
        if not hits:
            res.facts_text = f"Place: {entity.name}\nNo OpenStreetMap match."
            return res
        top = hits[0]
        lines = [f"Place: {entity.name}",
                 f"Best match: {top.get('display_name')}",
                 f"Coordinates: {top.get('lat')}, {top.get('lon')}",
                 f"OSM type: {top.get('category') or top.get('class')}/{top.get('type')}"]
        alts = [h.get("display_name") for h in hits[1:]]
        if alts:
            lines.append("Other candidates: " + " | ".join(alts))
        res.facts_text = "\n".join(lines)
        res.attributes = {
            "lat": float(top["lat"]), "lon": float(top["lon"]),
            "display_name": top.get("display_name"),
            "country_code": (top.get("address") or {}).get("country_code"),
            "osm": f"{top.get('osm_type')}/{top.get('osm_id')}",
            "candidates": len(hits), "status": "candidate",
        }
        return res
