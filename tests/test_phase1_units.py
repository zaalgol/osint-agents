"""Phase 1 unit tests: quotes, normalizers, parsing, WARC, fetcher, LLM client, schemas."""

from __future__ import annotations

import asyncio
import gzip
import io
import itertools
import json
from datetime import UTC
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from warcio.archiveiterator import ArchiveIterator

from osint.core.config import LocalModels, LocalRole, NetworkSettings
from osint.core.ontology import Ontology
from osint.evidence.parse import parse_artifact, should_parse
from osint.evidence.warc import build_warc
from osint.extraction.quotes import QuoteIndex
from osint.extraction.writer import parse_time
from osint.llm.local import LLMError, LocalLLM
from osint.net.http import Fetcher
from osint.orchestrator.runner import chunk_text
from osint.plugins.extractors.llm import schema_for, to_result
from osint.resolution.normalize import (
    domain_key,
    email_key,
    handle_key,
    phone_key,
    url_key,
    wallet_key,
)
from osint.text.normalize import name_key

NBSP = chr(0xA0)  # never write invisible characters literally
ONTO = Ontology.load([Path(__file__).resolve().parents[1] / "config/ontology.yaml"])

# --------------------------------------------------------------------------- quotes


DOC = ("The commander  Abu" + NBSP + "Example said: “We will strike again.”\n"
       "Later, the group – known as the Northern Front – claimed the attack in Testville.\n"
       "قال المُتحدّث "
       "إن الهجوم كان ناجحاً.")


def test_exact_quote():
    m = QuoteIndex(DOC).find("claimed the attack in Testville")
    assert m and m.method == "exact" and m.text(DOC) == "claimed the attack in Testville"


def test_normalized_quote_maps_back_to_original_text():
    qi = QuoteIndex(DOC)
    m = qi.find('Abu Example said: "We will strike again."')  # plain quotes, single space
    assert m and m.method == "normalized"
    assert m.text(DOC) == "Abu" + NBSP + "Example said: “We will strike again.”"
    m = qi.find("the group - known as the northern front - claimed")  # dashes + case
    assert m and "– known as the Northern Front –" in m.text(DOC)


def test_arabic_without_diacritics_matches():
    # LLMs often drop harakat/shadda; the original keeps them
    m = QuoteIndex(DOC).find("قال المتحدث")
    assert m is not None
    assert m.text(DOC).startswith("قال المُ")


def test_llm_swapping_double_for_single_quotes_still_matches():
    text = 'Officials said the U.S. has "total control over" the strait, a claim Iran denied.'
    m = QuoteIndex(text).find("the U.S. has 'total control over' the strait")
    assert m and m.text(text) == 'the U.S. has "total control over" the strait'


def test_elided_quote():
    m = QuoteIndex(DOC).find("Later, the group ... claimed the attack")
    assert m and m.method == "elided"
    assert m.text(DOC).startswith("Later, the group") and m.text(DOC).endswith("claimed the attack")


@pytest.mark.parametrize("fake", [
    "The commander vowed to strike again",            # paraphrase
    "claimed the bombing in Testville",              # one word changed
    "Northern Front claimed responsibility",         # plausible but absent
    "",
])
def test_paraphrases_and_inventions_are_rejected(fake):
    assert QuoteIndex(DOC).find(fake) is None


def test_occurrences():
    text = "Testville is calm. In TESTVILLE, police arrived. testville again."
    assert len(QuoteIndex(text).occurrences("Testville")) == 3


# --------------------------------------------------------------------------- normalizers


def test_strong_keys():
    assert email_key(" John.Doe@Example.ORG ") == "john.doe@example.org"
    assert email_key("not an email") is None
    assert phone_key("+972 (52) 123-4567") == "+972521234567"
    assert phone_key("00972521234567") == "+972521234567"
    assert phone_key("123") is None
    assert domain_key("https://www.Example.com/path") == "example.com"
    assert url_key("HTTPS://Example.com/a/b/#frag") == "https://example.com/a/b"
    assert wallet_key("0xAbCdEf0123456789aBcDeF0123456789AbCdEf01") == \
        "0xabcdef0123456789abcdef0123456789abcdef01"
    assert handle_key("https://t.me/SomeChannel") == "telegram:somechannel"
    assert handle_key("@SomeUser") == "someuser"
    assert name_key("  Al-Qa’ida ") == name_key("al qa'ida")


def test_chunk_text_covers_everything_with_overlap():
    text = ("Sentence number %d is here. " * 400) % tuple(range(400))
    chunks = chunk_text(text, 1000, 100, 100)
    assert chunks[0][0] == 0
    assert chunks[-1][0] + len(chunks[-1][1]) == len(text)
    for (o1, c1), (o2, _) in itertools.pairwise(chunks):
        assert o2 < o1 + len(c1)  # overlap, no gaps
    assert len(chunk_text(text, 1000, 100, 3)) == 3


@pytest.mark.parametrize("value,precision", [
    ("2026", "year"), ("2026-03", "month"), ("2026-03-01", "day"),
    ("2026-03-01T14:30", "exact"), (None, None), ("sometime", None),
])
def test_parse_time(value, precision):
    dt, p = parse_time(value)
    assert p == precision
    if precision:
        assert dt.tzinfo == UTC and dt.year == 2026


# --------------------------------------------------------------------------- parsing


ARTICLE = """<html><head><title>Front claims Testville attack</title></head><body>
<nav>Home | News | Contact</nav>
<article><h1>Front claims Testville attack</h1>
<p>The Northern Front claimed responsibility on Sunday for the attack in Testville, according to
a statement posted on its channel. The statement was signed by commander Abu Example.</p>
<p>Officials said the attack targeted a checkpoint. Analysts say the group has expanded its
operations in the region over the past year, recruiting through encrypted messaging apps.</p>
</article><footer>Copyright</footer></body></html>"""


def test_parse_html_extracts_article_text():
    doc = parse_artifact(ARTICLE.encode(), "text/html", "https://news.example/a1")
    assert doc is not None
    assert "claimed responsibility on Sunday" in doc.text
    assert "Home | News" not in doc.text
    assert doc.title == "Front claims Testville attack"
    assert len(doc.text_sha256) == 64


def test_rendered_dom_used_for_js_shell_pages():
    shell = b"<html><body><div id=app></div><script>render()</script></body></html>"
    doc = parse_artifact(shell, "text/html", "https://spa.example/", rendered_html=ARTICLE.encode())
    assert doc is not None and "rendered" in doc.parser


def test_should_parse():
    assert should_parse("text/html") and should_parse("application/pdf") and should_parse(None)
    assert not should_parse("application/json") and not should_parse("image/png")


# --------------------------------------------------------------------------- fetcher + WARC


def _settings(**kw) -> NetworkSettings:
    return NetworkSettings(per_host_interval_s=0, **kw)


class Streamed(httpx.AsyncByteStream):
    """Behaves like a real network body (not pre-read), so raw wire bytes can be streamed."""

    def __init__(self, data: bytes):
        self.data = data

    async def __aiter__(self):
        for i in range(0, len(self.data), 512):
            yield self.data[i:i + 512]


def test_fetcher_records_redirects_and_decodes_gzip():
    body = b"<html>hello evidence</html>"
    wire = gzip.compress(body)

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/old":
            return httpx.Response(301, headers={"Location": "/new"})
        return httpx.Response(200, stream=Streamed(wire), headers={
            "Content-Type": "text/html; charset=utf-8", "Content-Encoding": "gzip"})

    async def go():
        async with Fetcher(_settings(), transport=httpx.MockTransport(handler)) as f:
            return await f.fetch("https://site.example/old")

    r = asyncio.run(go())
    assert r.final_url == "https://site.example/new"
    assert r.redirects == ["https://site.example/old"]
    assert r.wire_body == wire and r.body == body
    assert r.content_type == "text/html" and r.charset == "utf-8"

    warc = build_warc(r)
    records = list(ArchiveIterator(io.BytesIO(warc)))
    types = [rec.rec_type for rec in records]
    assert types == ["warcinfo", "response", "request"]
    resp = records[1]
    assert resp.rec_headers.get_header("WARC-Target-URI") == "https://site.example/new"
    assert resp.http_headers.get_statuscode() == "200"


def test_fetcher_enforces_max_bytes():
    def handler(req):
        return httpx.Response(200, stream=Streamed(b"x" * 2000))

    async def go():
        async with Fetcher(_settings(max_bytes=1000), transport=httpx.MockTransport(handler)) as f:
            await f.fetch("https://big.example/")

    with pytest.raises(Exception, match="exceeds"):
        asyncio.run(go())


# --------------------------------------------------------------------------- LLM client + schema


def _llm(handler) -> LocalLLM:
    cfg = LocalModels(base_url="http://llm.test/v1",
                      roles={"agent": LocalRole(model="m", context=4096, temperature=0)})
    return LocalLLM(cfg, slots=1, transport=httpx.MockTransport(handler))


def test_schema_restricts_types_to_ontology():
    schema = schema_for(ONTO)
    ok = {"relevant": True, "relevance_reason": "r", "language": "en",
          "entities": [{"name": "X", "type": "person", "quote": "X"}]}
    to_result(schema.model_validate(ok))
    bad = {**ok, "entities": [{"name": "X", "type": "spaceship", "quote": "X"}]}
    with pytest.raises(ValidationError):
        schema.model_validate(bad)
    js = json.dumps(schema.model_json_schema())
    assert "armed_group" in js and "claim_of_responsibility" in js


def test_llm_retries_once_with_validation_error_then_succeeds():
    schema = schema_for(ONTO)
    good = {"relevant": False, "relevance_reason": "ads", "language": "en"}
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        calls.append(body)
        content = '{"relevant": "maybe"}' if len(calls) == 1 else json.dumps(good)
        return httpx.Response(200, json={"message": {"content": content},
                                         "prompt_eval_count": 10, "eval_count": 5})

    llm = _llm(handler)
    out = asyncio.run(llm.chat_json("agent", "sys", "user", schema))
    assert out.relevant is False
    assert len(calls) == 2 and "did not validate" in calls[1]["messages"][-1]["content"]
    assert calls[0]["think"] is False and calls[0]["format"]["title"] == "Extraction"
    assert calls[0]["options"]["num_ctx"] == 4096
    assert len(llm.usage_log) == 2


def test_llm_falls_back_when_model_rejects_think_flag():
    schema = schema_for(ONTO)
    seen = []

    def handler(req):
        body = json.loads(req.content)
        seen.append("think" in body)
        if "think" in body:
            return httpx.Response(400, json={"error": "model does not support thinking"})
        return httpx.Response(200, json={"message": {"content": json.dumps(
            {"relevant": True, "relevance_reason": "r", "language": "en"})}})

    llm = _llm(handler)
    asyncio.run(llm.chat_json("agent", "s", "u", schema))
    asyncio.run(llm.chat_json("agent", "s", "u", schema))
    assert seen == [True, False, False]  # remembered per model


def test_llm_gives_up_after_retry():
    def handler(req):
        return httpx.Response(200, json={"message": {"content": "not json"}})

    with pytest.raises(LLMError):
        asyncio.run(_llm(handler).chat_json("agent", "s", "u", schema_for(ONTO)))
