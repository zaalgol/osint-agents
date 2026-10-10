"""Strong-identifier normalization: canonical keys for exact cross-investigation matching."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

from osint.text.normalize import name_key

_DIGITS = re.compile(r"\D+")


def email_key(v: str) -> str | None:
    v = v.strip().strip("<>").lower()
    return v if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v) else None


def phone_key(v: str) -> str | None:
    s = v.strip()
    plus = s.startswith(("+", "00"))
    digits = _DIGITS.sub("", s)
    if s.startswith("00"):
        digits = digits[2:]
    if not 7 <= len(digits) <= 15:
        return None
    return ("+" if plus else "") + digits


def domain_key(v: str) -> str | None:
    v = v.strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    v = v.split("/")[0].split(":")[0].rstrip(".")
    v = v.removeprefix("www.")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return v if "." in v else None


def url_key(v: str) -> str | None:
    try:
        p = urlsplit(v.strip())
    except ValueError:
        return None
    if not p.scheme or not p.hostname:
        return None
    host = domain_key(p.hostname) or p.hostname.lower()
    path = p.path.rstrip("/") or "/"
    return urlunsplit((p.scheme.lower(), host, path, p.query, ""))


def wallet_key(v: str) -> str | None:
    v = v.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", v):          # EVM: case-insensitive
        return v.lower()
    if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", v) or re.fullmatch(
        r"(bc1|tb1)[0-9a-z]{25,87}", v.lower()
    ):
        return v if not v.lower().startswith(("bc1", "tb1")) else v.lower()
    if re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", v):  # TRON
        return v
    return v if len(v) >= 20 and " " not in v else None


def handle_key(v: str) -> str | None:
    """Online accounts / channels: 'telegram:@name', '@name', t.me/name ..."""
    v = v.strip()
    platform = ""
    m = re.match(r"(?:https?://)?(?:www\.)?(t\.me|telegram\.me|x\.com|twitter\.com|"
                 r"instagram\.com|facebook\.com|youtube\.com|tiktok\.com)/(@?[\w.\-]+)", v, re.IGNORECASE)
    if m:
        platform = {"t.me": "telegram", "telegram.me": "telegram", "twitter.com": "x"}.get(
            m.group(1).lower(), m.group(1).lower().split(".")[0])
        v = m.group(2)
    elif ":" in v and not v.startswith("@"):
        platform, v = v.split(":", 1)
    handle = v.strip().lstrip("@").lower()
    if not handle or " " in handle:
        return None
    return f"{platform.lower()}:{handle}" if platform else handle


def ip_key(v: str) -> str | None:
    import ipaddress

    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError:
        return None


STRONG_KEYS = {
    "ip_address": ip_key,
    "email": email_key,
    "phone": phone_key,
    "domain": domain_key,
    "url": url_key,
    "crypto_wallet": wallet_key,
    "online_account": handle_key,
    "channel": handle_key,
}


def strong_key(entity_type: str, value: str, ontology=None) -> str | None:
    fn = STRONG_KEYS.get(entity_type)
    if fn is None and ontology is not None:
        for anc in ontology._ancestors(ontology.entity_types, entity_type):
            fn = STRONG_KEYS.get(anc)
            if fn:
                break
    return fn(value) if fn else None


__all__ = ["STRONG_KEYS", "name_key", "strong_key"]
