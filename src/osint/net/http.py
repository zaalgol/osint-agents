"""Policy-enforcing HTTP fetcher.

Every network request from a plugin goes through here, so rate limits, proxying, user
agent and size limits are enforced in one place. It records exactly what was sent and
received (the wire bytes and headers), which the WARC capture needs.
"""

from __future__ import annotations

import asyncio
import time
import zlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Self
from urllib.parse import urlsplit

import httpx

from osint.core.config import NetworkSettings


class FetchError(RuntimeError):
    pass


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    reason: str
    http_version: str
    request_headers: list[tuple[str, str]]
    response_headers: list[tuple[str, str]]
    wire_body: bytes            # as transmitted (may be content-encoded)
    body: bytes                 # decoded payload
    fetched_at: datetime
    resolved_ip: str | None = None
    redirects: list[str] = field(default_factory=list)
    route: str = "direct"           # direct | vpn
    blocked: str | None = None      # why the final response looks like a block (if it does)
    attempts: list[dict] = field(default_factory=list)  # earlier routes tried and why they failed

    @property
    def content_type(self) -> str | None:
        for k, v in self.response_headers:
            if k.lower() == "content-type":
                return v.split(";")[0].strip().lower() or None
        return None

    @property
    def charset(self) -> str | None:
        for k, v in self.response_headers:
            if k.lower() == "content-type" and "charset=" in v.lower():
                return v.lower().split("charset=")[1].split(";")[0].strip().strip('"')
        return None


def _decode(body: bytes, encoding: str | None) -> bytes:
    enc = (encoding or "").lower().strip()
    if not enc or enc == "identity":
        return body
    if enc in ("gzip", "x-gzip"):
        return zlib.decompress(body, 16 + zlib.MAX_WBITS)
    if enc == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    if enc == "br":
        import brotli

        return brotli.decompress(body)
    raise FetchError(f"unsupported content-encoding {encoding!r}")


BLOCK_STATUSES = {401, 403, 407, 429, 451, 503}
CHALLENGE_MARKERS = ("cf-chl", "challenge-platform", "just a moment...", "attention required",
                     "captcha", "access denied", "request blocked", "ddos-guard",
                     "are you a robot", "unusual traffic", "perimeterx", "px-captcha")
NETWORK_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                  httpx.RemoteProtocolError, httpx.ProxyError)


def block_reason(status: int, body: bytes) -> str | None:
    """Heuristic: does this response look like an anti-bot block rather than content?"""
    if status in BLOCK_STATUSES:
        return f"HTTP {status}"
    if len(body) < 30_000:
        head = body[:8000].decode("utf-8", "ignore").lower()
        for m in CHALLENGE_MARKERS:
            if m in head:
                return f"challenge page ({m})"
    return None


class Fetcher:
    """Fetch over the direct route; on a block or network refusal, retry over the VPN route.

    direct  settings.proxy (None = your normal connection)
    vpn     settings.vpn_proxy, e.g. socks5://127.0.0.1:1080 from your VPN app or wireproxy
    A host that blocked the direct route stays on the VPN for the rest of the run
    (sticky), and every result records which route produced it.
    """

    def __init__(self, settings: NetworkSettings, transport: httpx.AsyncBaseTransport | None = None,
                 vpn_transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self._transport = transport          # tests inject httpx.MockTransport
        self._vpn_transport = vpn_transport
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._host_locks: dict[str, asyncio.Lock] = {}
        self._host_last: dict[str, float] = {}
        self.vpn_hosts: set[str] = set()     # hosts that blocked the direct route
        self._doh_cache: dict[str, tuple[str, float]] = {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    @property
    def vpn_available(self) -> bool:
        return bool(self.settings.vpn_proxy) or self._vpn_transport is not None

    def _client_get(self, route: str = "direct") -> httpx.AsyncClient:
        if route not in self._clients:
            if route == "vpn":
                transport, proxy = self._vpn_transport, self.settings.vpn_proxy
            else:
                transport, proxy = self._transport, self.settings.proxy
            self._clients[route] = httpx.AsyncClient(
                transport=transport,
                proxy=proxy if transport is None else None,
                timeout=self.settings.timeout_s,
                follow_redirects=False,  # we follow manually to record the chain
                headers={
                    "User-Agent": self.settings.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                              "application/json;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8,*;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                },
            )
        return self._clients[route]

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()

    async def _polite(self, url: str, route: str) -> None:
        host = f"{route}:{urlsplit(url).hostname or ''}"
        lock = self._host_locks.setdefault(host, asyncio.Lock())
        async with lock:
            wait = self._host_last.get(host, 0) + self.settings.per_host_interval_s - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._host_last[host] = time.monotonic()

    async def fetch(self, url: str, params: dict | None = None, max_redirects: int = 10) -> FetchResult:
        host = urlsplit(url).hostname or ""
        use_vpn_first = host in self.vpn_hosts and self.vpn_available
        routes = ["vpn"] if use_vpn_first else ["direct"]
        if not use_vpn_first and self.vpn_available and self.settings.vpn_fallback:
            routes.append("vpn")
        attempts: list[dict] = []
        for i, route in enumerate(routes):
            last = i == len(routes) - 1
            try:
                res = await self._fetch_route(url, params, max_redirects, route)
            except NETWORK_ERRORS as e:
                attempts.append({"route": route, "error": f"{type(e).__name__}: {e}"[:300]})
                if last:
                    raise FetchError(f"{url}: unreachable ({'; '.join(a['error'] for a in attempts)})"
                                     ) from e
                self.vpn_hosts.add(host)
                continue
            res.blocked = block_reason(res.status, res.body)
            res.attempts = attempts
            if res.blocked and not last:
                attempts.append({"route": route, "error": f"blocked: {res.blocked}"})
                self.vpn_hosts.add(host)
                continue
            return res
        raise FetchError(f"{url}: no route")  # unreachable

    async def _doh(self, host: str) -> str | None:
        """Resolve via DNS-over-HTTPS, sent over the VPN route (cached by TTL)."""
        import ipaddress

        try:
            ipaddress.ip_address(host)
            return host                      # already an IP
        except ValueError:
            pass
        hit = self._doh_cache.get(host)
        if hit and hit[1] > time.monotonic():
            return hit[0]
        client = self._client_get("vpn")
        for rtype, num in (("A", 1), ("AAAA", 28)):
            r = await client.get(self.settings.doh_url, params={"name": host, "type": rtype},
                                 headers={"accept": "application/dns-json"})
            if r.status_code != 200:
                continue
            answers = [a for a in r.json().get("Answer", []) if a.get("type") == num]
            if answers:
                ip, ttl = answers[-1]["data"], max(60, int(answers[-1].get("TTL", 300)))
                self._doh_cache[host] = (ip, time.monotonic() + ttl)
                return ip
        return None

    async def _build(self, client: httpx.AsyncClient, url: str, route: str) -> httpx.Request:
        """On the VPN route with DoH: connect to the DoH-resolved IP while keeping the real
        hostname for the Host header and TLS SNI/certificate verification."""
        u = httpx.URL(url)
        if route != "vpn" or not self.settings.vpn_doh or self._vpn_transport is not None:
            return client.build_request("GET", url)
        ip = await self._doh(u.host)
        if ip is None or ip == u.host:
            return client.build_request("GET", url)
        host_header = u.host if u.port in (None, 80, 443) else f"{u.host}:{u.port}"
        target = u.copy_with(host=ip)
        return client.build_request("GET", target, headers={"Host": host_header},
                                    extensions={"sni_hostname": u.host})

    async def _fetch_route(self, url: str, params: dict | None, max_redirects: int,
                           route: str) -> FetchResult:
        client = self._client_get(route)
        redirects: list[str] = []
        current = str(httpx.URL(url, params=params)) if params else url
        for _ in range(max_redirects + 1):
            await self._polite(current, route)
            req = await self._build(client, current, route)
            resp = await client.send(req, stream=True)
            try:
                resolved_ip = None
                if req.url.host != httpx.URL(current).host:
                    resolved_ip = req.url.host        # DoH-resolved address we connected to
                elif route == "direct" and (stream := resp.extensions.get("network_stream")):
                    addr = stream.get_extra_info("server_addr")
                    if addr:
                        resolved_ip = str(addr[0])
                if resp.is_redirect and "location" in resp.headers:
                    redirects.append(current)
                    # resolve against the hostname URL (the request may have gone to an IP)
                    current = str(httpx.URL(current).join(resp.headers["location"]))
                    continue
                headers = [(k, v) for k, v in resp.headers.multi_items()]
                if resp.is_stream_consumed:
                    # some transports hand back already-read (and decoded) responses
                    wire = body = resp.content
                    headers = [(k, v) for k, v in headers if k.lower() != "content-encoding"]
                else:
                    chunks, size = [], 0
                    async for chunk in resp.aiter_raw():
                        size += len(chunk)
                        if size > self.settings.max_bytes:
                            raise FetchError(
                                f"{current}: response exceeds {self.settings.max_bytes} bytes")
                        chunks.append(chunk)
                    wire = b"".join(chunks)
                    body = _decode(wire, resp.headers.get("content-encoding"))
            finally:
                await resp.aclose()
            if len(body) > self.settings.max_bytes:
                raise FetchError(f"{current}: response exceeds {self.settings.max_bytes} bytes")
            return FetchResult(
                url=url,
                final_url=current,
                status=resp.status_code,
                reason=resp.reason_phrase,
                http_version=resp.http_version,
                request_headers=[(k, v) for k, v in req.headers.multi_items()],
                response_headers=headers,
                wire_body=wire,
                body=body,
                fetched_at=datetime.now(UTC),
                resolved_ip=resolved_ip,
                redirects=redirects,
                route=route,
            )
        raise FetchError(f"{url}: too many redirects")
