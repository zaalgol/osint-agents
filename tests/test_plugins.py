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
