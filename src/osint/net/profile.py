"""Network profiles per investigation.

standard   direct -> VPN (WARP + DoH) -> browser, the default ladder
anonymous  everything through Tor: fetches, screenshots, YouTube, enrichers, timestamps.
           There is no direct attempt and no VPN fallback, because a direct first try would
           reveal the collector's IP to the target. Fails closed if Tor isn't available.
"""

from __future__ import annotations

PROFILES = ("standard", "anonymous")


def profile_of(investigation) -> str:
    return ((investigation.config or {}).get("network_profile") or "standard")


def apply_profile(settings, profile: str, investigation_id: int | None = None):
    """Return a settings copy for this profile (anonymous: Tor-only, verified first)."""
    if profile not in PROFILES:
        raise ValueError(f"unknown network profile {profile!r}; use {PROFILES}")
    if profile == "standard":
        return settings
    from osint.net import tor

    tor.ensure(settings, investigation_id)        # raises TorUnavailable: fail closed
    s = settings.model_copy(deep=True)
    via_tor = tor.socks_url(settings, investigation_id)
    s.network.proxy = via_tor                      # the "direct" route itself goes via Tor
    s.network.browser_proxy = tor.browser_socks_url(settings)
    s.network.vpn_proxy = None
    s.network.vpn_fallback = False
    s.network.vpn_doh = False                      # Tor resolves names at the exit
    s.evidence.archive_org = False
    # SearXNG queries the engines itself: use the instance that sends them through Tor
    s.searxng.url = s.searxng.tor_url
    _check_searxng_tor(s.searxng.url)
    return s


def _check_searxng_tor(url: str) -> None:
    import httpx

    from osint.net.tor import TorUnavailable

    try:
        httpx.get(f"{url}/healthz", timeout=10).raise_for_status()
    except Exception as e:  # noqa: BLE001
        raise TorUnavailable(f"the Tor-routed SearXNG at {url} isn't up "
                             f"(docker compose up -d searxng-tor): {e}") from None
