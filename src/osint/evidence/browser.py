"""Visual capture with Playwright: full-page screenshot, PDF render and rendered DOM.

This shows what a human would have seen, which matters for JS-heavy and social pages
where the raw HTML says little. It's a second load of the page, so its own timestamp
is recorded next to the HTTP fetch time.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

log = logging.getLogger(__name__)

# Serialize the live DOM *including open shadow roots*. page.content() omits shadow DOM,
# so sites built from web components (e.g. MSN) would otherwise yield an empty shell.
FLATTEN_JS = """
() => {
  const SKIP = new Set(['SCRIPT','STYLE','NOSCRIPT','TEMPLATE','SVG','CANVAS','IFRAME','LINK','META']);
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const attr = s => s.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
  function ser(node) {
    if (node.nodeType === Node.TEXT_NODE) return esc(node.textContent);
    if (node.nodeType !== Node.ELEMENT_NODE) return '';
    if (SKIP.has(node.tagName.toUpperCase())) return '';
    const tag = node.tagName.toLowerCase();
    let attrs = '';
    for (const a of node.attributes) {
      if (['href','src','datetime','title','lang','dir','class','id'].includes(a.name))
        attrs += ` ${a.name}="${attr(a.value)}"`;
    }
    let inner = '';
    if (node.shadowRoot) for (const c of node.shadowRoot.childNodes) inner += ser(c);
    for (const c of node.childNodes) inner += ser(c);
    return `<${tag}${attrs}>${inner}</${tag}>`;
  }
  const title = document.title ? `<title>${esc(document.title)}</title>` : '';
  return `<!doctype html><html lang="${attr(document.documentElement.lang || '')}"><head>`
       + `<meta charset="utf-8">${title}</head>${ser(document.body)}</html>`;
}
"""


def playwright_proxy(url: str) -> dict:
    """socks5://user:pass@host:port -> Playwright's {server, username, password}."""
    from urllib.parse import urlsplit

    u = urlsplit(url)
    out = {"server": f"{u.scheme}://{u.hostname}:{u.port}"}
    if u.username:
        out["username"] = u.username
        out["password"] = u.password or ""
    return out


@dataclass
class BrowserCapture:
    screenshot_png: bytes | None
    pdf: bytes | None
    rendered_html: bytes | None
    captured_at: datetime
    final_url: str | None
    error: str | None = None


class BrowserCapturer:
    def __init__(self, user_agent: str, proxy: str | None, timeout_s: float, max_pages: int = 3):
        self.user_agent = user_agent
        self.proxy = proxy
        self.timeout_ms = int(timeout_s * 1000)
        self._sem = asyncio.Semaphore(max_pages)
        self._pw = None
        self._browser = None
        self._lock = asyncio.Lock()

    async def _ensure(self):
        async with self._lock:
            if self._browser is None:
                from playwright.async_api import async_playwright

                self._pw = await async_playwright().start()
                # CPU rendering: keep the GPU free for the local LLM
                launch = {"headless": True, "args": ["--disable-gpu"]}
                if self.proxy:
                    launch["proxy"] = {"server": self.proxy}
                self._browser = await self._pw.chromium.launch(**launch)
        return self._browser

    async def capture(self, url: str, proxy: str | None = None) -> BrowserCapture:
        async with self._sem:
            try:
                browser = await self._ensure()
                opts = {"user_agent": self.user_agent, "viewport": {"width": 1366, "height": 900},
                        "java_script_enabled": True, "accept_downloads": False}
                if proxy:  # same route as the HTTP fetch (e.g. VPN after a block)
                    opts["proxy"] = playwright_proxy(proxy)
                ctx = await browser.new_context(**opts)
                try:
                    page = await ctx.new_page()
                    try:
                        await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
                    except Exception:  # noqa: BLE001 - busy pages never go idle; settle for load
                        await page.goto(url, wait_until="load", timeout=self.timeout_ms)
                    at = datetime.now(UTC)
                    png = await page.screenshot(full_page=True, type="png", timeout=self.timeout_ms)
                    try:
                        html = (await page.evaluate(FLATTEN_JS)).encode("utf-8")
                    except Exception as e:  # noqa: BLE001 - fall back to the plain DOM
                        log.debug("shadow-DOM flatten failed for %s: %s", url, e)
                        html = (await page.content()).encode("utf-8")
                    try:
                        pdf = await page.pdf(print_background=True)
                    except Exception as e:  # noqa: BLE001 - PDF is a bonus; keep the screenshot
                        log.debug("pdf render failed for %s: %s", url, e)
                        pdf = None
                    return BrowserCapture(png, pdf, html, at, page.url)
                finally:
                    await ctx.close()
            except Exception as e:  # noqa: BLE001 - capture failure must not lose the HTTP evidence
                log.warning("browser capture failed for %s: %s", url, e)
                return BrowserCapture(None, None, None, datetime.now(UTC), None, error=str(e)[:500])

    async def aclose(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._pw is not None:
            await self._pw.stop()
            self._pw = None
