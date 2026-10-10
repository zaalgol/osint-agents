"""Anonymous network profile: Tor-only, fail closed, isolated circuits, no local leaks."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from test_phase4 import resp

from osint.core.config import NetworkSettings, Settings
from osint.net import profile as prof
from osint.net import tor
from osint.net.http import Fetcher, FetchError, is_loopback


def _settings() -> Settings:
    s = Settings()
    s.network.vpn_proxy = "socks5://127.0.0.1:40000"
    return s


def test_socks_url_isolates_investigations():
    s = _settings()
    a, b = tor.socks_url(s, 1), tor.socks_url(s, 2)
    assert a != b and a.startswith("socks5://inv1:") and a.endswith(f":{s.tor.socks_port}")


def test_standard_profile_is_untouched(monkeypatch):
    monkeypatch.setattr(tor, "ensure", lambda *a: pytest.fail("standard must not touch Tor"))
    s = _settings()
    assert prof.apply_profile(s, "standard", 1) is s


def test_anonymous_profile_routes_everything_through_tor(monkeypatch):
    monkeypatch.setattr(tor, "ensure", lambda *a: None)
    monkeypatch.setattr(prof, "_check_searxng_tor", lambda url: None)
    s = _settings()
    a = prof.apply_profile(s, "anonymous", 7)
    assert a.network.proxy == tor.socks_url(s, 7)
    assert a.network.browser_proxy == tor.browser_socks_url(s)      # Chromium: no SOCKS auth
    assert a.network.vpn_proxy is None and not a.network.vpn_fallback and not a.network.vpn_doh
    assert a.searxng.url == s.searxng.tor_url
    assert s.network.proxy is None and s.network.vpn_proxy      # original settings unchanged


def test_anonymous_fails_closed_without_tor(monkeypatch):
    def down(*a):
        raise tor.TorUnavailable("no tor")

    monkeypatch.setattr(tor, "ensure", down)
    with pytest.raises(tor.TorUnavailable):
        prof.apply_profile(_settings(), "anonymous", 1)
    with pytest.raises(ValueError):
        prof.apply_profile(_settings(), "sneaky", 1)


def test_ensure_refuses_when_exit_is_not_tor(monkeypatch):
    s = _settings()
    s.tor.auto_start = False
    monkeypatch.setattr(tor, "check_exit",
                        lambda *a, **k: tor.TorStatus(True, 100, is_tor=False, exit_ip="1.2.3.4"))
    with pytest.raises(tor.TorUnavailable):
        tor.ensure(s, 1)


def test_loopback_services_bypass_the_proxy_and_never_redirect_out():
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and not is_loopback("example.org")

    def local(req):
        if req.url.path == "/out":
            return httpx.Response(302, headers={"location": "https://example.org/"})
        return resp(200, '{"results": []}', "application/json")

    async def go():
        net = NetworkSettings(per_host_interval_s=0, proxy="socks5://inv1:x@127.0.0.1:9050")
        async with Fetcher(net, transport=httpx.MockTransport(local)) as f:
            ok = await f.fetch("http://127.0.0.1:8889/search")
            tor_fetch = await f.fetch("https://example.org/")
            with pytest.raises(FetchError, match="off-host"):
                await f.fetch("http://127.0.0.1:8889/out")
            return ok, tor_fetch, set(f._clients)

    ok, tor_fetch, clients = asyncio.run(go())
    assert ok.route == "local" and ok.status == 200 and clients == {"local", "direct"}
    assert tor_fetch.route == "proxy"           # labelled as proxied, not "direct"
