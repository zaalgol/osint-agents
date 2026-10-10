"""Phase 4: VPN fallback + account guard, public collectors, enrichers, exporters, UI."""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from osint.core.config import NetworkSettings
from osint.net.http import Fetcher, block_reason


class Streamed(httpx.AsyncByteStream):
    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        yield self.data


def resp(status: int, body: bytes | str, ctype: str = "text/html") -> httpx.Response:
    data = body.encode() if isinstance(body, str) else body
    return httpx.Response(status, stream=Streamed(data), headers={"Content-Type": ctype})


# --------------------------------------------------------------------------- network


def _net(**kw) -> NetworkSettings:
    return NetworkSettings(per_host_interval_s=0, **kw)


def test_block_detection():
    assert block_reason(403, b"x") == "HTTP 403"
    assert block_reason(200, b"<title>Just a moment...</title> cf-chl") is not None
    assert block_reason(200, b"<html>" + b"news about captcha systems " * 2000) is None  # big page
    assert block_reason(200, b"<html>normal article</html>") is None


def test_vpn_fallback_on_block_and_sticky_host():
    direct_calls, vpn_calls = [], []

    def direct(req):
        direct_calls.append(str(req.url))
        return resp(403, "Forbidden")

    def vpn(req):
        vpn_calls.append(str(req.url))
        return resp(200, "<html>real content</html>")

    async def go():
        async with Fetcher(_net(vpn_proxy="socks5://vpn.test:1080"),
                           transport=httpx.MockTransport(direct),
                           vpn_transport=httpx.MockTransport(vpn)) as f:
            a = await f.fetch("https://site.test/a")
            b = await f.fetch("https://site.test/b")     # sticky: straight to VPN
            return a, b, f.vpn_hosts

    a, b, hosts = asyncio.run(go())
    assert a.route == "vpn" and a.status == 200 and a.blocked is None
    assert a.attempts == [{"route": "direct", "error": "blocked: HTTP 403"}]
    assert b.route == "vpn" and direct_calls == ["https://site.test/a"]
    assert hosts == {"site.test"} and len(vpn_calls) == 2


def test_vpn_fallback_on_network_error():
    def direct(req):
        raise httpx.ConnectError("connection refused", request=req)

    async def go():
        async with Fetcher(_net(), transport=httpx.MockTransport(direct),
                           vpn_transport=httpx.MockTransport(lambda r: resp(200, "ok page"))) as f:
            return await f.fetch("https://blocked.test/")

    r = asyncio.run(go())
    assert r.route == "vpn" and "ConnectError" in r.attempts[0]["error"]


def test_without_vpn_the_block_is_returned_and_marked():
    async def go():
        async with Fetcher(_net(), transport=httpx.MockTransport(
                lambda r: resp(429, "slow down"))) as f:
            return await f.fetch("https://rate.test/")

    r = asyncio.run(go())
    assert r.route == "direct" and r.blocked == "HTTP 429"


def test_account_sources_are_refused(pg_settings):
    from osint.analyst.tools import AnalystTools, ToolError
    from osint.core.context import App
    from osint.core.plugins import Collector, PluginError, check_collector_allowed

    class Needy(Collector):
        name = "needs_login"
        requires_account = True

        async def collect(self, params, ctx):
            yield None

    with pytest.raises(PluginError, match="account"):
        check_collector_allowed(Needy, pg_settings)
    pg_settings.collection.allow_account_sources = True
    check_collector_allowed(Needy, pg_settings)
    pg_settings.collection.allow_account_sources = False
    app = App(pg_settings)
    app.registry.register(Needy)
    t = AnalystTools(app.session_factory, app.ontology, app.registry, app.raw_store, 1)
    with pytest.raises(ToolError, match="account"):
        t.request_collection("needs_login", {}, "x")


# --------------------------------------------------------------------------- collectors

TG_PAGE = """<html><body>
<div class="tgme_channel_info_header_title"><span>Test Channel</span></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="testchan/101">
 <div class="tgme_widget_message_text js-message_text">First post<br>second line</div>
 <a class="tgme_widget_message_date" href="https://t.me/testchan/101"><time datetime="2026-10-01T10:00:00+00:00">x</time></a>
 <span class="tgme_widget_message_views">1.2K</span></div></div>
<div class="tgme_widget_message_wrap"><div class="tgme_widget_message js-widget_message" data-post="testchan/102">
 <div class="tgme_widget_message_forwarded_from_name">Other Chan</div>
 <a class="tgme_widget_message_photo_wrap 1 2" href="https://t.me/testchan/102" style="width:800px;background-image:url('https://cdn1.telesco.pe/file/abc.jpg')"></a>
 <div class="tgme_widget_message_text js-message_text">Threat statement against <a href="https://evil.test/x">the port</a></div>
 <a class="tgme_widget_message_date" href="https://t.me/testchan/102"><time datetime="2026-10-02T11:00:00+00:00">x</time></a></div></div>
<a class="tme_messages_more" data-before="101" href="/s/testchan?before=101"></a>
</body></html>"""


def test_telegram_preview_parsing():
    from osint.plugins.collectors.telegram_public import channel_name, parse_preview

    info, posts, before = parse_preview(TG_PAGE.encode())
    assert info["title"] == "Test Channel" and before == 101
    assert [p["id"] for p in posts] == [101, 102]
    assert posts[0]["text"] == "First post\nsecond line"
    assert posts[1]["forwarded_from"] == "Other Chan" and posts[1]["links"] == ["https://evil.test/x"]
    assert posts[1]["photos"] == ["https://cdn1.telesco.pe/file/abc.jpg"] and posts[0]["photos"] == []
    assert channel_name("https://t.me/s/testchan") == "testchan" == channel_name("@testchan")
    with pytest.raises(ValueError):
        channel_name("not a channel!")


@pytest.mark.integration
def test_telegram_collector_posts_and_incremental_refresh(pg_settings):
    from osint.core.context import App
    from osint.plugins.collectors.telegram_public import TelegramPublicCollector

    pg_settings.evidence.screenshots = False
    pg_settings.network.per_host_interval_s = 0
    app = App(pg_settings)
    pages = {"https://t.me/s/testchan": TG_PAGE,
             "https://t.me/s/testchan?before=101": "<html><body></body></html>",
             "https://cdn1.telesco.pe/file/abc.jpg": bytes.fromhex("ffd8ff") + b" fake jpeg"}

    async def run(coll, params):
        out = []
        async with app.services(http_transport=httpx.MockTransport(
                lambda r: resp(200, pages[str(r.url)], "image/jpeg" if r.url.path.endswith(".jpg")
                               else "text/html")), browser=False) as svc:
            ctx = app.context(None, **svc)
            async for item in coll.collect(coll.parse_params(params), ctx):
                out.append(item)
        return out

    c = TelegramPublicCollector()
    items = asyncio.run(run(c, {"channels": ["testchan"], "max_posts": 10}))
    posts = [i for i in items if i.meta.platform_id and "/" in i.meta.platform_id]
    assert [p.meta.platform_id for p in posts] == ["telegram:testchan/102",
                                                   "telegram:testchan/102:photo1",
                                                   "telegram:testchan/101"]
    photo = posts[1]
    assert photo.mime == "image/jpeg" and photo.meta.extra["post"] == "https://t.me/testchan/102"
    posts = [posts[0], posts[2]]
    assert posts[0].meta.posted_at.isoformat().startswith("2026-10-02")
    assert b"Post: https://t.me/testchan/102" in posts[0].data
    assert posts[0].meta.extra["derived_from"]["sha256_page"]
    cp = c.on_refresh(c.checkpoint())
    assert cp == {"newest": {"testchan": 102}}
    c2 = TelegramPublicCollector()
    c2.restore(cp)
    again = asyncio.run(run(c2, {"channels": ["testchan"]}))
    assert not [i for i in again if "/" in (i.meta.platform_id or "")]  # nothing new


def test_wayback_pick_and_vtt():
    from osint.plugins.collectors.wayback import pick
    from osint.plugins.collectors.youtube import vtt_to_transcript

    rows = [[str(i)] for i in range(10)]
    assert pick(rows, "latest", 2) == [["9"], ["8"]]
    assert pick(rows, "earliest", 2) == [["0"], ["1"]]
    assert len(pick(rows, "spread", 3)) == 3
    vtt = ("WEBVTT\nKind: captions\n\n00:00:01.000 --> 00:00:03.000\n<c>hello</c> world\n\n"
           "00:00:03.000 --> 00:00:05.000\nhello world\n\n00:01:05.500 --> 00:01:07.000\nnext line\n")
    assert vtt_to_transcript(vtt) == "[00:00:01] hello world\n[00:01:05] next line"


@pytest.mark.integration
def test_gdelt_collector_schedules_article_fetches(pg_settings):
    from osint.core.context import App
    from osint.core.models import FollowUp
    from osint.plugins.collectors.gdelt import GdeltCollector

    pg_settings.network.per_host_interval_s = 0
    app = App(pg_settings)
    body = json.dumps({"articles": [{"url": "https://news.test/1"}, {"url": "https://news.test/2"}]})

    async def go():
        c = GdeltCollector()
        async with app.services(http_transport=httpx.MockTransport(
                lambda r: resp(200, body, "application/json")), browser=False) as svc:
            return [i async for i in c.collect(c.parse_params({"queries": ["houthi"]}),
                                               app.context(None, **svc))]

    items = asyncio.run(go())
    assert not items[0].parse and items[0].meta.extra["query"] == "houthi"
    assert [f.params["urls"][0] for f in items if isinstance(f, FollowUp)] == \
        ["https://news.test/1", "https://news.test/2"]


# --------------------------------------------------------------------------- enrichers


@pytest.fixture
def app4(pg_settings):
    from osint.core.context import App

    pg_settings.evidence.screenshots = False
    pg_settings.network.per_host_interval_s = 0
    return App(pg_settings)


def _entity(app, etype: str, name: str, strong: str | None = None) -> tuple[int, int]:
    from osint.resolution.resolver import add_ref
    from osint.storage.db import Entity, EntityAlias, Investigation

    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"p4-{uuid.uuid4().hex[:8]}")
        s.add(inv)
        s.flush()
        e = Entity(type=etype, canonical_name=name, strong_key=strong)
        s.add(e)
        s.flush()
        s.add(EntityAlias(entity_id=e.id, alias=name, alias_norm=name.lower(), lang="und"))
        add_ref(s, inv.id, "entity", e.id, "t")
        return inv.id, e.id


def _enrich(app, inv, eid, enricher, handler, monkeypatch=None):
    from osint.enrichment.base import entity_view, persist_enrichment

    async def go():
        async with app.services(http_transport=httpx.MockTransport(handler), browser=False) as svc:
            with app.session_factory() as s:
                view = entity_view(s, eid)
            return await enricher.enrich(view, app.context(inv, **svc))

    res = asyncio.run(go())
    with app.session_factory() as s, s.begin():
        out = persist_enrichment(s, app, inv, eid, enricher.ident, enricher.name, res)
    return res, out


@pytest.mark.integration
def test_rdap_enricher_writes_cited_registrar_relation(app4, monkeypatch):
    from osint.plugins.enrichers import rdap
    from osint.storage.db import Entity, EvidenceLink, Relation

    dom = f"x{uuid.uuid4().hex[:6]}.test"
    inv, eid = _entity(app4, "domain", dom, dom)
    monkeypatch.setattr(rdap, "_dns", lambda d: {"A": ["203.0.113.7"]})
    data = {"events": [{"eventAction": "registration", "eventDate": "2024-02-03T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]]}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}]}
    res, out = _enrich(app4, inv, eid, rdap.RdapEnricher(),
                       lambda r: resp(200, json.dumps(data), "application/rdap+json"))
    assert "Registrar: Example Registrar Inc" in res.facts_text and out["relations"] == 2
    with app4.session_factory() as s:
        rels = {r.type: r for r in s.scalars(select(Relation).where(Relation.src_entity_id == eid))}
        assert set(rels) == {"registered_by", "resolves_to"}
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                 EvidenceLink.target_id == rels["registered_by"].id))
        assert ev.quote_verified and ev.quote_original == "Registrar: Example Registrar Inc"
        assert s.get(Entity, eid).attributes["rdap"]["registrar"] == "Example Registrar Inc"


@pytest.mark.integration
def test_btc_and_geocode_enrichers(app4):
    from osint.plugins.enrichers.btc import BtcEnricher
    from osint.plugins.enrichers.geocode import GeocodeEnricher
    from osint.storage.db import Entity

    addr = "bc1q" + "a" * 38
    inv, eid = _entity(app4, "crypto_wallet", addr, addr)
    stats = {"chain_stats": {"tx_count": 3, "funded_txo_sum": 150_000_000, "spent_txo_sum": 50_000_000},
             "mempool_stats": {"tx_count": 0}}
    res, _ = _enrich(app4, inv, eid, BtcEnricher(), lambda r: resp(200, json.dumps(stats), "application/json"))
    assert "Balance at capture: 1.00000000 BTC" in res.facts_text
    inv2, loc = _entity(app4, "location", f"Mokha{uuid.uuid4().hex[:4]}")
    hits = [{"lat": "13.32", "lon": "43.25", "display_name": "Mokha, Taiz, Yemen", "category": "place",
             "type": "town", "osm_type": "node", "osm_id": 1, "address": {"country_code": "ye"}},
            {"lat": "-38.4", "lon": "-73.9", "display_name": "Mocha Island, Chile"}]
    res, _ = _enrich(app4, inv2, loc, GeocodeEnricher(), lambda r: resp(200, json.dumps(hits), "application/json"))
    with app4.session_factory() as s:
        g = s.get(Entity, loc).attributes["geocode"]
    assert g["country_code"] == "ye" and g["status"] == "candidate" and g["candidates"] == 2
    assert "Mocha Island, Chile" in res.facts_text


UN_XML = """<CONSOLIDATED_LIST><INDIVIDUALS><INDIVIDUAL><FIRST_NAME>ABU</FIRST_NAME>
<SECOND_NAME>TESTMAN</SECOND_NAME><UN_LIST_TYPE>Al-Qaida</UN_LIST_TYPE>
<REFERENCE_NUMBER>QDi.999</REFERENCE_NUMBER><LISTED_ON>2010-01-01</LISTED_ON></INDIVIDUAL></INDIVIDUALS>
<ENTITIES><ENTITY><FIRST_NAME>NORTHERN TEST FRONT</FIRST_NAME><UN_LIST_TYPE>Al-Qaida</UN_LIST_TYPE>
<REFERENCE_NUMBER>QDe.999</REFERENCE_NUMBER><LISTED_ON>2015-05-05</LISTED_ON>
<ENTITY_ALIAS><ALIAS_NAME>NTF</ALIAS_NAME></ENTITY_ALIAS></ENTITY></ENTITIES></CONSOLIDATED_LIST>"""
SDN = '9001,"BLUE HAND BRIGADE","-0- ","SDGT"\n9002,"TESTMAN, Abu","individual","SDGT"\n'
ALT = '9001,1,"aka","BLUE HAND","-0- "\n'


def test_sanctions_list_parsing():
    from osint.plugins.enrichers.sanctions import parse_ofac, parse_un

    un = parse_un(UN_XML.encode())
    assert {e.kind for e in un} == {"individual", "entity"}
    ent = next(e for e in un if e.kind == "entity")
    assert ent.names == ["NORTHERN TEST FRONT", "NTF"] and "QDe.999" in ent.line
    ofac = parse_ofac(SDN.encode(), ALT.encode())
    assert ofac[0].names == ["BLUE HAND BRIGADE", "BLUE HAND"] and ofac[1].kind == "individual"


@pytest.mark.integration
def test_sanctions_org_becomes_relation_but_person_only_review(app4):
    from osint.plugins.enrichers.sanctions import SanctionsEnricher
    from osint.storage.db import EvidenceLink, Relation, ReviewItem

    SanctionsEnricher._cache = {}
    files = {"consolidated.xml": UN_XML, "sdn.csv": SDN, "alt.csv": ALT}

    def handler(r):
        body = files.get(str(r.url).rsplit("/", 1)[-1].lower())
        return resp(200, body, "text/plain") if body is not None else resp(404, "not found")

    inv, org = _entity(app4, "armed_group", "Northern Test Front")
    _res, out = _enrich(app4, inv, org, SanctionsEnricher(), handler)
    assert out["relations"] >= 1 and out["reviews"] == 0
    with app4.session_factory() as s:
        rel = s.scalar(select(Relation).where(Relation.src_entity_id == org,
                                              Relation.type == "designated_by"))
        ev = s.scalar(select(EvidenceLink).where(EvidenceLink.target_type == "relation",
                                                 EvidenceLink.target_id == rel.id))
        assert "QDe.999" in ev.quote_original
    inv2, person = _entity(app4, "person", "Abu Testman")
    _res, out = _enrich(app4, inv2, person, SanctionsEnricher(), handler)
    assert out.get("relations", 0) == 0 and out["reviews"] == 2  # UN + OFAC, both for review
    with app4.session_factory() as s:
        kinds = set(s.scalars(select(ReviewItem.kind).where(ReviewItem.investigation_id == inv2)))
        assert kinds == {"sanctions_match"}
        assert s.scalar(select(Relation).where(Relation.src_entity_id == person)) is None


# --------------------------------------------------------------------------- quality guards


def test_enrichment_only_relations_are_not_offered_to_the_llm():
    from pathlib import Path

    from osint.core.ontology import Ontology
    from osint.plugins.extractors.llm import schema_for

    onto = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])
    js = json.dumps(schema_for(onto).model_json_schema())
    assert "designated_by" not in js and "member_of" in js


def test_weak_relation_quotes_are_rejected():
    from osint.core.models import EntityRef, ExtractedRelation
    from osint.extraction.writer import ExtractionWriter

    r = ExtractedRelation(type="located_in", src=EntityRef(name="Houthi rebels", type="armed_group"),
                          dst=EntityRef(name="Yemen", type="location"), quote="Yemen")
    assert "too short" in ExtractionWriter._weak_relation_quote("Yemen", r)
    assert "neither" in ExtractionWriter._weak_relation_quote("the weather was hot today", r)
    assert ExtractionWriter._weak_relation_quote("Houthi rebels control parts of Yemen", r) is None
    assert ExtractionWriter._weak_relation_quote("They fired from positions in Yemen", r) is None


# --------------------------------------------------------------------------- exporters + UI


@pytest.mark.integration
def test_exporters_and_ui(pg_settings, tmp_path):
    import hashlib

    import stix2
    from starlette.testclient import TestClient

    from osint.core.context import App
    from osint.core.models import (
        CapturedItem,
        CaptureMeta,
        EntityRef,
        ExtractedEntity,
        ExtractedRelation,
        ExtractionResult,
    )
    from osint.evidence.capture import persist_item
    from osint.extraction.writer import ExtractionWriter
    from osint.plugins.exporters.formats import FtmExporter, GexfExporter, Scope, StixExporter
    from osint.resolution.resolver import add_ref
    from osint.storage.db import Capture, Document, Investigation

    app = App(pg_settings)
    tag = uuid.uuid4().hex[:5]
    text = f"Commander Ray{tag} leads the Iron{tag} Brigade in Port{tag} City."
    with app.session_factory() as s, s.begin():
        inv = Investigation(name=f"exp-{tag}")
        s.add(inv)
        s.flush()
        art, _ = persist_item(s, app.raw_store, CapturedItem(
            data=f"<html><script>alert(1)</script>{text}</html>".encode(),
            meta=CaptureMeta(url="https://x.test/a"), mime="text/html",
            extra_captures=[]), actor="t")
        s.add(Capture(artifact_id=art.id, kind="rendered_html", sha256=art.sha256,
                      sha512=art.sha512, path=art.path))
        add_ref(s, inv.id, "artifact", art.id, "t")
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        w = ExtractionWriter(s, app.ontology, inv.id, d, actor="t")
        w.write(ExtractionResult(
            entities=[ExtractedEntity(name=f"Ray{tag}", type="person", quote=f"Ray{tag}"),
                      ExtractedEntity(name=f"Iron{tag} Brigade", type="armed_group", quote=f"Iron{tag} Brigade")],
            relations=[ExtractedRelation(type="leader_of", src=EntityRef(name=f"Ray{tag}", type="person"),
                                         dst=EntityRef(name=f"Iron{tag} Brigade", type="armed_group"),
                                         quote=f"Commander Ray{tag} leads the Iron{tag} Brigade")]))
        inv_id = inv.id
    with app.session_factory() as s:
        scope = Scope(s, inv_id)
        stix_path = StixExporter().write(scope, tmp_path / "x.stix.json")
        ftm_path = FtmExporter().write(scope, tmp_path / "x.ftm.jsonl")
        gexf_path = GexfExporter().write(scope, tmp_path / "x.gexf")
    bundle = stix2.parse(stix_path.read_text(encoding="utf-8"), allow_custom=True)
    types = {o["type"] for o in bundle.objects}
    assert {"threat-actor", "identity", "relationship", "report"} <= types
    rel = next(o for o in bundle.objects if o["type"] == "relationship")
    assert rel["x_osint_evidence"][0]["quote"].startswith("Commander Ray")
    ftm = [json.loads(x) for x in ftm_path.read_text(encoding="utf-8").splitlines()]
    assert any(e["schema"] == "Membership" for e in ftm)
    assert gexf_path.read_text(encoding="utf-8").startswith("<?xml")

    from osint.ui.app import create_app

    c = TestClient(create_app(app))
    assert c.get("/").status_code == 200
    ev = c.get(f"/api/inv/{inv_id}/evidence").json()["artifacts"][0]
    cap = next(x for x in ev["captures"] if x["kind"] == "rendered_html")
    r = c.get(f"/capture/{cap['id']}")
    assert r.headers["content-type"].startswith("text/plain")          # never rendered as HTML
    assert "sandbox" in r.headers["content-security-policy"]
    g = c.get(f"/api/inv/{inv_id}/graph").json()
    assert len(g["nodes"]) == 2 and g["edges"][0]["data"]["label"] == "leader_of"


@pytest.mark.integration
def test_sanctions_ambiguous_alias_and_generic_names_go_to_review(app4):
    from osint.plugins.enrichers.sanctions import SanctionsEnricher
    from osint.storage.db import Relation

    SanctionsEnricher._cache = {}
    tag = uuid.uuid4().hex[:4].upper()
    un = f"""<CONSOLIDATED_LIST><ENTITIES><ENTITY><FIRST_NAME>THE SHADOW{tag}S</FIRST_NAME>
    <UN_LIST_TYPE>X</UN_LIST_TYPE><REFERENCE_NUMBER>XEe.1</REFERENCE_NUMBER><LISTED_ON>2020</LISTED_ON>
    <ENTITY_ALIAS><ALIAS_NAME>PARTISANS {tag}</ALIAS_NAME></ENTITY_ALIAS></ENTITY></ENTITIES></CONSOLIDATED_LIST>"""
    sdn = (f'7001,"OTHER GROUP {tag}","-0- ","SDGT"\n'
           f'7002,"VANGUARD{tag}","-0- ","RUSSIA"\n')
    alt = f'7001,1,"aka","PARTISANS {tag}","-0- "\n'
    files = {"consolidated.xml": un, "sdn.csv": sdn, "alt.csv": alt}

    def handler(r):
        body = files.get(str(r.url).rsplit("/", 1)[-1].lower())
        return resp(200, body, "text/plain") if body is not None else resp(404, "not found")

    # matched via an alias that two listed parties share -> review, no relation
    inv, amb = _entity(app4, "armed_group", f"Partisans {tag}")
    _res, out = _enrich(app4, inv, amb, SanctionsEnricher(), handler)
    assert out["reviews"] == 2 and out.get("relations", 0) == 0
    # single-word name -> review, no relation
    inv2, gen = _entity(app4, "organization", f"Vanguard{tag}")
    _res, out = _enrich(app4, inv2, gen, SanctionsEnricher(), handler)
    assert out["reviews"] == 1 and out.get("relations", 0) == 0
    # unambiguous primary name -> fact
    inv3, ok = _entity(app4, "armed_group", f"The Shadow{tag}s")
    _res, out = _enrich(app4, inv3, ok, SanctionsEnricher(), handler)
    with app4.session_factory() as s:
        assert s.scalar(select(Relation).where(Relation.src_entity_id == ok,
                                               Relation.type == "designated_by")) is not None
        assert s.scalar(select(Relation).where(Relation.src_entity_id.in_([amb, gen]))) is None


@pytest.mark.integration
def test_retraction_hides_relation_everywhere(app4):
    import hashlib

    from osint.analyst.tools import AnalystTools
    from osint.core.models import CaptureMeta, EntityRef, ExtractedRelation, ExtractionResult
    from osint.evidence.ingest import ingest_bytes
    from osint.extraction.retract import cleanup_disallowed, retract
    from osint.extraction.writer import ExtractionWriter
    from osint.linking.network import build_graph
    from osint.storage.db import Document, Entity, Relation

    inv, e1 = _entity(app4, "armed_group", f"Grp{uuid.uuid4().hex[:5]} Front")
    with app4.session_factory() as s:
        name = s.get(Entity, e1).canonical_name
    text = f"{name} is backed by Iran and operates in Yemen."
    with app4.session_factory() as s, s.begin():
        art, _ = ingest_bytes(s, app4.raw_store, text.encode() + uuid.uuid4().bytes,
                              CaptureMeta(url="https://r.test"), actor="t")
        d = Document(artifact_id=art.id, extractor="t", text=text,
                     text_sha256=hashlib.sha256(text.encode()).hexdigest())
        s.add(d)
        s.flush()
        w = ExtractionWriter(s, app4.ontology, inv, d, actor="extractor:llm@0.1.0")
        w.write(ExtractionResult(relations=[
            ExtractedRelation(type="designated_by", src=EntityRef(name=name, type="armed_group"),
                              dst=EntityRef(name="Iran", type="organization"),
                              quote=f"{name} is backed by Iran")]))
        rel_id = s.scalar(select(Relation.id).where(Relation.src_entity_id == e1))
    with app4.session_factory() as s, s.begin():
        assert rel_id in cleanup_disallowed(s, app4.ontology)
    t = AnalystTools(app4.session_factory, app4.ontology, app4.registry, app4.raw_store, inv)
    assert t.get_entity(e1)["relations"] == []
    with app4.session_factory() as s:
        assert e1 not in build_graph(s, inv).nodes
        assert s.get(Relation, rel_id).attributes["retracted"]["by"] == "cleanup"
    with app4.session_factory() as s, s.begin(), pytest.raises(ValueError):
        retract(s, 999_999_999, "x", "t")


@pytest.mark.integration
def test_citation_retraction_keeps_relation_until_last_citation_and_fails_gate(app4):
    import hashlib

    from osint.analyst.tools import AnalystTools
    from osint.core.models import CaptureMeta, EntityRef, ExtractedRelation, ExtractionResult
    from osint.evidence.ingest import ingest_bytes
    from osint.extraction.retract import retract_citation
    from osint.extraction.writer import ExtractionWriter
    from osint.reports.verify import verify_report
    from osint.storage.db import Document, EvidenceLink, Relation

    tag = uuid.uuid4().hex[:5]
    a, b = f"Kael{tag} Group", f"Mor{tag} Front"
    inv, _ = _entity(app4, "armed_group", a)
    ids = []
    for sentence in (f"{a} is affiliated with {b} in the north.", f"{a} is affiliated with {b} again."):
        with app4.session_factory() as s, s.begin():
            art, _ = ingest_bytes(s, app4.raw_store, sentence.encode() + uuid.uuid4().bytes,
                                  CaptureMeta(url=f"https://c.test/{uuid.uuid4().hex}"), actor="t")
            d = Document(artifact_id=art.id, extractor="t", text=sentence,
                         text_sha256=hashlib.sha256(sentence.encode()).hexdigest())
            s.add(d)
            s.flush()
            ExtractionWriter(s, app4.ontology, inv, d, actor="t").write(ExtractionResult(relations=[
                ExtractedRelation(type="affiliated_with", src=EntityRef(name=a, type="armed_group"),
                                  dst=EntityRef(name=b, type="armed_group"),
                                  quote=f"{a} is affiliated with {b}")]))
            ids.append(s.scalar(select(EvidenceLink.id).where(EvidenceLink.document_id == d.id)))
    with app4.session_factory() as s, s.begin():
        out = retract_citation(s, ids[0], "wrong source", "test")
        rel_id = int(out["target"].split(":")[1])
    assert out["remaining_valid_citations"] is True
    t = AnalystTools(app4.session_factory, app4.ontology, app4.registry, app4.raw_store, inv)
    assert t.get_evidence([ids[0]])[0]["error"].startswith("citation retracted")
    v = asyncio.run(verify_report(app4.session_factory, app4.raw_store, inv,
                                  f"{a} is affiliated with {b} in the north [E:{ids[0]}]."))
    assert not v.ok and v.unresolved == 1
    with app4.session_factory() as s, s.begin():
        out = retract_citation(s, ids[1], "also wrong", "test")
        assert out.get("relation_retracted") is True
        assert s.get(Relation, rel_id).attributes["retracted"]


def test_vpn_route_resolves_with_doh_and_keeps_hostname_for_tls():
    def vpn(req):
        if req.url.path == "/dns-query":
            name = req.url.params["name"]
            return httpx.Response(200, json={"Answer": [
                {"type": 1, "data": "203.0.113.9", "TTL": 300}]} if name == "blocked.test" else {})
        return resp(200, "page")

    async def go():
        f = Fetcher(_net(vpn_proxy="socks5://vpn.test:1080"), vpn_transport=httpx.MockTransport(vpn))
        ip = await f._doh("blocked.test")
        f._vpn_transport = None          # let _build apply DoH (the vpn client already exists)
        req = await f._build(f._client_get("vpn"), "https://blocked.test/a?b=1", "vpn")
        direct = await f._build(f._client_get("direct"), "https://blocked.test/a", "direct")
        await f.aclose()
        return ip, req, direct

    ip, req, direct = asyncio.run(go())
    assert ip == "203.0.113.9"
    assert req.url.host == "203.0.113.9" and req.url.path == "/a" and req.url.query == b"b=1"
    assert req.headers["Host"] == "blocked.test"
    assert req.extensions["sni_hostname"] == "blocked.test"     # TLS still verifies the hostname
    assert direct.url.host == "blocked.test"                     # direct route untouched


def test_browser_route_captures_sites_that_block_http_clients(pg_settings):
    from datetime import UTC, datetime

    from osint.core.context import App
    from osint.evidence.browser import BrowserCapture, BrowserFetch
    from osint.evidence.capture import capture_url

    pg_settings.network.per_host_interval_s = 0
    pg_settings.network.vpn_proxy = None
    app = App(pg_settings)

    class FakeBrowser:
        async def fetch(self, url, proxy=None):
            return BrowserFetch(200, "OK", url, [("user-agent", "x")],
                                [("content-type", "text/html; charset=utf-8")],
                                b"<html>real article</html>",
                                BrowserCapture(b"png", None, b"<html>dom</html>", datetime.now(UTC), url))

        async def capture(self, url, proxy=None):
            raise AssertionError("not used")

    async def go():
        async with app.services(http_transport=httpx.MockTransport(lambda r: resp(403, "denied")),
                                browser=False) as svc:
            ctx = app.context(None, with_db=False, **{**svc, "browser": FakeBrowser()})
            return await capture_url(ctx, "https://antibot.test/story", "test")

    item = asyncio.run(go())
    assert item.meta.extra["route"] == "browser" and item.meta.http_status == 200
    assert item.data == b"<html>real article</html>" and item.parse
    assert item.meta.extra["route_attempts"][-1]["error"] == "blocked: HTTP 403"
    assert {str(getattr(c.kind, "value", c.kind)) for c in item.extra_captures} >= {"warc", "screenshot_png"}


def test_unreachable_site_falls_back_to_browser(pg_settings):
    from datetime import UTC, datetime

    from osint.core.context import App
    from osint.evidence.browser import BrowserCapture, BrowserFetch
    from osint.evidence.capture import capture_url

    pg_settings.network.per_host_interval_s = 0
    app = App(pg_settings)

    class FakeBrowser:
        async def fetch(self, url, proxy=None):
            return BrowserFetch(200, "OK", url, [], [("content-type", "text/html")], b"<html>ok</html>",
                                BrowserCapture(None, None, None, datetime.now(UTC), url))

    def tarpit(req):
        raise httpx.ReadTimeout("held open", request=req)

    async def go():
        async with app.services(http_transport=httpx.MockTransport(tarpit), browser=False) as svc:
            ctx = app.context(None, with_db=False, **{**svc, "browser": FakeBrowser()})
            return await capture_url(ctx, "https://tarpit.test/a", "test")

    item = asyncio.run(go())
    assert item.meta.extra["route"] == "browser" and "ReadTimeout" in item.meta.extra["route_attempts"][0]["error"]


EU_XML = """<?xml version="1.0"?><export xmlns="http://eu.europa.ec/fpi/fsd/export">
<sanctionEntity euReferenceNumber="EU.1.1" logicalId="1">
 <regulation programme="YEM" entryIntoForceDate="2022-03-01"/><subjectType code="enterprise"/>
 <nameAlias wholeName="ПАРТИЗАНИ" nameLanguage="BG"/>
 <nameAlias wholeName="THE RIVER LEGION" nameLanguage="EN"/>
 <nameAlias wholeName="RIVERLEGION" nameLanguage="EN"/></sanctionEntity>
<sanctionEntity euReferenceNumber="EU.2.2" logicalId="2"><subjectType code="person"/>
 <nameAlias wholeName="Abu Testman"/></sanctionEntity></export>"""
UK_CSV = """Report Date: 08-Oct-2026
Unique ID,Name 6,Name 1,Name 2,Name 3,Name 4,Name 5,Name type,Regime Name,Designation Type,Date Designated
YEM9,The River Legion,,,,,,Primary Name,Yemen,Entity,01/03/2022
YEM9,RIVERLEGION,,,,,,Alias,Yemen,Entity,01/03/2022
YEM9,RIVERLEGION,,,,,,Alias,Yemen,Entity,01/03/2022
SHP1,Some Ship,,,,,,Primary Name,Yemen,Ship,01/03/2022
"""


def test_eu_and_uk_list_parsing():
    from osint.plugins.enrichers.sanctions import parse_eu, parse_uk

    eu = parse_eu(EU_XML.encode())
    assert [e.kind for e in eu] == ["entity", "individual"]
    assert eu[0].names[0] == "THE RIVER LEGION"            # English name leads the citation
    assert "EU.1.1 [YEM]" in eu[0].line and "2022-03-01" in eu[0].line
    uk = parse_uk(UK_CSV.encode())
    assert len(uk) == 1 and uk[0].names == ["The River Legion", "RIVERLEGION"]   # ships skipped
    assert uk[0].line.startswith("UK Sanctions List YEM9 [Yemen]: The River Legion")


def test_same_party_on_several_lists_is_not_ambiguous_but_name_collision_is():
    from osint.plugins.enrichers.sanctions import ListEntry, SanctionsEnricher, _keys, _parties

    def entry(src, ref, *names):
        e = ListEntry(src, src, ref, "entity", list(names), "")
        e.keys = _keys(e.names)
        return e

    es = [entry("eu", "1", "The River Legion", "Riverlegion"),
          entry("uk", "9", "The River Legion", "RIVERLEGION"),
          entry("ofac", "5", "OTHER PARTY", "RIVER LEGION")]          # shares only the name
    SanctionsEnricher._cache = {"by_id": {f"{e.source}:{e.ref}": e for e in es}}
    ids = [f"{e.source}:{e.ref}" for e in es]
    assert _parties(ids[:2], {"river legion"}) == 1
    assert _parties(ids, {"river legion"}) == 2
    # primary name on both lists, no other shared name (UK adds "Hezbollah"): same party
    es = [entry("ofac", "7", "HIZBALLAH", "PARTY OF GOD"), entry("uk", "C3", "Hizballah", "Hezbollah")]
    SanctionsEnricher._cache = {"by_id": {f"{e.source}:{e.ref}": e for e in es}}
    assert _parties(["ofac:7", "uk:C3"], {"hizballah"}) == 1
    SanctionsEnricher._cache = {}
