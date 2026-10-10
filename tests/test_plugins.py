import asyncio
import textwrap

import pytest

from osint.core.plugins import Collector, Enricher, PluginError, PluginRegistry, build_registry
from osint.plugins.collectors.echo import EchoCollector, EchoParams


def test_entry_point_discovery_finds_builtin():
    reg = build_registry()
    assert reg.get("collector", "echo") is EchoCollector


def test_drop_in_dir_discovery(tmp_path):
    (tmp_path / "my_enricher.py").write_text(textwrap.dedent("""
        from osint.core.plugins import Enricher

        class Whois(Enricher):
            name = "whois_test"
            entity_types = {"domain"}
            async def enrich(self, entity, ctx):
                return []
    """))
    (tmp_path / "_private.py").write_text("raise RuntimeError('must not be imported')")
    (tmp_path / "broken.py").write_text("this is not python")
    reg = PluginRegistry()
    reg.discover_dirs([tmp_path])  # broken file is logged, not fatal
    cls = reg.get("enricher", "whois_test")
    assert cls().ident == "enricher:whois_test@0.1.0"


def test_duplicates_and_abstract_rejected():
    reg = PluginRegistry()
    reg.register(EchoCollector)
    reg.register(EchoCollector)  # same class twice is idempotent

    class Other(Collector):
        name = "echo"

        async def collect(self, params, ctx):
            yield None

    with pytest.raises(PluginError, match="duplicate"):
        reg.register(Other)

    class Incomplete(Enricher):
        name = "incomplete"

    with pytest.raises(PluginError, match="abstract"):
        reg.register(Incomplete)
    with pytest.raises(PluginError):
        reg.get("collector", "nope")


def test_echo_collector_resumes_from_checkpoint():
    c = EchoCollector()
    params = c.parse_params({"items": ["a", "b", "c"]})
    assert isinstance(params, EchoParams)

    async def take(n):
        out = []
        async for item in c.collect(params, ctx=None):
            out.append((item.data, item.meta.url))
            if len(out) == n:
                break
        return out

    first = asyncio.run(take(2))
    assert [d for d, _ in first] == [b"a", b"b"]
    # "b" was handed out but the consumer never came back for more, so it counts as not
    # yet persisted. Resume re-delivers it (at-least-once; ingest dedups by hash).
    assert c.checkpoint() == {"cursor": 1}
    c2 = EchoCollector()  # a fresh process after a crash
    c2.restore(c.checkpoint())
    c = c2
    rest = asyncio.run(take(10))
    assert rest == [(b"b", "manual://echo/1"), (b"c", "manual://echo/2")]


def test_paste_urls_map_to_raw_endpoints():
    from osint.plugins.collectors.paste import paste_ref

    assert paste_ref("https://pastebin.com/AbCd1234") == (
        "pastebin.com", "AbCd1234", "https://pastebin.com/raw/AbCd1234")
    assert paste_ref("https://pastebin.com/raw/AbCd1234")[2] == "https://pastebin.com/raw/AbCd1234"
    assert paste_ref("https://paste.ee/p/xYz12")[2] == "https://paste.ee/r/xYz12"
    assert paste_ref("https://gist.github.com/someone/0a1b2c3d")[2] == \
        "https://gist.githubusercontent.com/someone/0a1b2c3d/raw"
    assert paste_ref("https://rentry.co/abc-def") == ("rentry.co", "abc-def", None)
    assert paste_ref("https://pastebin.com/login") is None           # site pages aren't pastes
    assert paste_ref("https://example.org/AbCd1234") is None


@pytest.mark.integration
def test_paste_collector_captures_page_and_raw_and_searches(pg_settings):
    import asyncio
    import json

    import httpx

    from osint.core.context import App
    from osint.core.models import CapturedItem, FollowUp
    from osint.plugins.collectors.paste import PasteCollector

    pg_settings.evidence.screenshots = False
    pg_settings.network.per_host_interval_s = 0
    app = App(pg_settings)
    hits = {"results": [{"url": "https://pastebin.com/Zz9Yy8Xx"},
                        {"url": "https://pastebin.com/login"},
                        {"url": "https://news.test/a"}]}

    def handler(r):
        u = str(r.url)
        if "/search" in u:
            return httpx.Response(200, json=hits)
        if u == "https://pastebin.com/raw/AbCd1234":
            return httpx.Response(200, text="wallet bc1qxyz\nhandle @someone",
                                  headers={"Content-Type": "text/plain"})
        return httpx.Response(200, text="<html><body>paste page</body></html>",
                              headers={"Content-Type": "text/html"})

    async def go():
        out = []
        async with app.services(http_transport=httpx.MockTransport(handler), browser=False) as svc:
            ctx = app.context(None, **svc)
            c = PasteCollector()
            params = c.parse_params({"urls": ["https://pastebin.com/AbCd1234"],
                                     "queries": ["red sea"], "hosts": ["pastebin.com"]})
            async for item in c.collect(params, ctx):
                out.append(item)
        return out

    items = asyncio.run(go())
    caps = [i for i in items if isinstance(i, CapturedItem)]
    page, raw = caps[0], caps[1]
    assert page.meta.platform_id == "paste:pastebin.com:AbCd1234" and page.parse is False
    assert raw.meta.platform_id.endswith(":raw") and raw.parse and raw.mime == "text/plain"
    assert raw.meta.extra["paste"]["page"] == "https://pastebin.com/AbCd1234"
    assert json.loads(caps[2].data)["results"]                      # search result page kept
    follow = [i for i in items if isinstance(i, FollowUp)]
    assert follow[0].plugin == "paste" and follow[0].params["urls"] == ["https://pastebin.com/Zz9Yy8Xx"]
