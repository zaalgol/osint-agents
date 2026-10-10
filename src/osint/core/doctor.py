"""Dependency checks (`osint doctor` and the GUI's System page)."""

from __future__ import annotations

import shutil
import subprocess

import httpx
from sqlalchemy import text

from osint.core.config import get_models_config, get_settings
from osint.core.context import App


def run_checks() -> list[tuple[str, bool, str]]:
    settings, models = get_settings(), get_models_config()
    results: list[tuple[str, bool, str]] = []

    def check(name: str, fn) -> None:
        try:
            results.append((name, True, fn() or "ok"))
        except Exception as e:  # noqa: BLE001 - doctor reports every failure, never crashes
            results.append((name, False, f"{type(e).__name__}: {e}"[:160]))

    def pg() -> str:
        from osint.storage.session import make_engine

        with make_engine(settings).connect() as c:
            ver = c.scalar(text("SHOW server_version"))
            vec = c.scalar(text("SELECT extversion FROM pg_extension WHERE extname='vector'"))
            head = c.scalar(text("SELECT version_num FROM alembic_version"))
        if not vec:
            raise RuntimeError("pgvector extension missing (run osint init)")
        return f"postgres {ver}, pgvector {vec}, schema {head}"

    def neo() -> str:
        from osint.storage.graph import make_driver

        with make_driver(settings) as d:
            d.verify_connectivity()
            info = d.get_server_info()
        return f"{info.agent}"

    def searx() -> str:
        r = httpx.get(f"{settings.searxng.url}/search",
                      params={"q": "test", "format": "json"}, timeout=20)
        r.raise_for_status()
        return f"json api ok ({len(r.json().get('results', []))} results)"

    def ollama() -> str:
        base = models.local.base_url.removesuffix("/v1")
        tags = httpx.get(f"{base}/api/tags", timeout=10).json()
        have = {m["name"] for m in tags.get("models", [])}
        have |= {n.removesuffix(":latest") for n in have}
        want = {role: r.model for role, r in models.local.roles.items()}
        missing = [f"{role}={m}" for role, m in want.items() if m not in have]
        if missing:
            raise RuntimeError("missing models: " + ", ".join(missing))
        return ", ".join(f"{k}={v}" for k, v in want.items())

    def claude() -> str:
        exe = shutil.which(models.claude.binary)
        if not exe:
            raise RuntimeError(f"{models.claude.binary!r} not on PATH")
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30,
                             check=False)
        return out.stdout.strip() or out.stderr.strip()

    def gpu() -> str:
        out = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.used,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=15, check=True,
        )
        return out.stdout.strip()

    def plugins() -> str:
        reg = App(settings).registry
        return f"{len(reg.list())} plugins"

    def vpn() -> str:
        if not settings.network.vpn_proxy:
            return "off (no network.vpn_proxy; blocked sites stay blocked)"
        r = httpx.get("https://www.cloudflare.com/cdn-cgi/trace", proxy=settings.network.vpn_proxy,
                      timeout=20)
        info = dict(line.split("=", 1) for line in r.text.splitlines() if "=" in line)
        return f"{settings.network.vpn_proxy}: exit {info.get('loc', '?')}, warp={info.get('warp', '?')}"

    def tor() -> str:
        from osint.net import tor as torlib

        st = torlib.status(settings)
        if not st.running:
            return "not running (only anonymous investigations need it: osint tor start)"
        if not st.is_tor:
            raise RuntimeError(f"running but traffic does NOT exit via Tor: {st.detail}")
        return f"running, exits via Tor ({st.exit_ip})"

    def searx_tor() -> str:
        try:
            httpx.get(f"{settings.searxng.tor_url}/healthz", timeout=10).raise_for_status()
        except httpx.HTTPError:
            return "down (only anonymous investigations need it: docker compose up -d searxng-tor)"
        return f"up at {settings.searxng.tor_url}"

    def blocklists() -> str:
        bl = App(settings).raw_store.blocklist
        return f"{len(bl)} blocked hash(es) in {bl.dir}"

    for name, fn in [("postgres", pg), ("neo4j", neo), ("searxng", searx), ("ollama", ollama),
                     ("claude cli", claude), ("gpu", gpu), ("plugins", plugins), ("vpn", vpn),
                     ("tor", tor), ("searxng-tor", searx_tor), ("blocklists", blocklists)]:
        check(name, fn)

    return results
