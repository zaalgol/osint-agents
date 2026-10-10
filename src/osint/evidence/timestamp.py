"""Trusted timestamps for manifest digests: RFC 3161 (a TSA) and OpenTimestamps (Bitcoin).

Only the 32-byte SHA-256 digest is sent, never content. Requests go through the
configured network proxy (OPSEC: the TSA/calendar still sees that *someone* stamped
something, and when).

RFC 3161: DER TimeStampReq built by hand (sha256 imprint, nonce, certReq); the reply's
status must be granted, and the token must contain our digest. Full cryptographic
verification of the token uses `openssl ts -verify` with the TSA's CA certificate,
which is stored next to the proof.

OpenTimestamps: the digest is submitted to public calendars. The reply is a *pending*
timestamp, which becomes Bitcoin-anchored after a few hours (`ots upgrade <file>`, then
`ots verify`). A standard detached .ots file is written per calendar.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import httpx

SHA256_ALGID = bytes.fromhex("300d06096086480165030402010500")  # AlgorithmIdentifier sha256
OTS_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
OTS_SHA256_OP = bytes([0x08])
DEFAULT_TSA = "https://freetsa.org/tsr"
DEFAULT_TSA_CERTS = ["https://freetsa.org/files/cacert.pem", "https://freetsa.org/files/tsa.crt"]
DEFAULT_CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]


class TimestampError(RuntimeError):
    pass


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(value: int) -> bytes:
    b = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")  # leading 0 keeps it positive
    return _der(0x02, b)


def build_tsq(digest: bytes, nonce: int) -> bytes:
    imprint = _der(0x30, SHA256_ALGID + _der(0x04, digest))
    body = _der_int(1) + imprint + _der_int(nonce) + _der(0x01, bytes([0xFF]))
    return _der(0x30, body)


def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Returns (tag, content_start, content_end)."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def tsr_status(tsr: bytes) -> int:
    tag, start, _ = _read_tlv(tsr, 0)            # TimeStampResp SEQUENCE
    if tag != 0x30:
        raise TimestampError("not a DER TimeStampResp")
    tag, s2, _ = _read_tlv(tsr, start)           # PKIStatusInfo SEQUENCE
    tag, s3, e3 = _read_tlv(tsr, s2)             # status INTEGER
    if tag != 0x02:
        raise TimestampError("malformed PKIStatusInfo")
    return int.from_bytes(tsr[s3:e3], "big")


@dataclass
class StampResult:
    method: str
    authority: str
    proof: bytes
    status: str            # complete | pending
    extra_files: dict[str, bytes]


async def stamp_rfc3161(digest: bytes, client: httpx.AsyncClient, tsa_url: str = DEFAULT_TSA,
                        cert_urls: list[str] | None = None) -> StampResult:
    req = build_tsq(digest, secrets.randbits(63))
    r = await client.post(tsa_url, content=req,
                          headers={"Content-Type": "application/timestamp-query"})
    if r.status_code != 200:
        raise TimestampError(f"TSA {tsa_url}: HTTP {r.status_code}")
    tsr = r.content
    status = tsr_status(tsr)
    if status not in (0, 1):
        raise TimestampError(f"TSA refused the request (PKIStatus {status})")
    if digest not in tsr:
        raise TimestampError("TSA token does not contain our digest")
    extra = {}
    for url in cert_urls if cert_urls is not None else DEFAULT_TSA_CERTS:
        try:
            c = await client.get(url)
            if c.status_code == 200:
                extra[url.rsplit("/", 1)[-1]] = c.content
        except httpx.HTTPError:
            pass
    return StampResult("rfc3161", tsa_url, tsr, "complete", extra)


async def stamp_opentimestamps(digest: bytes, client: httpx.AsyncClient,
                               calendars: list[str] | None = None) -> list[StampResult]:
    out = []
    for cal in calendars or DEFAULT_CALENDARS:
        try:
            r = await client.post(f"{cal}/digest", content=digest,
                                  headers={"Accept": "application/vnd.opentimestamps.v1",
                                           "User-Agent": "osint-agents"})
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and r.content:
            ots = OTS_MAGIC + bytes([1]) + OTS_SHA256_OP + digest + r.content
            out.append(StampResult("opentimestamps", cal, ots, "pending", {}))
    if not out:
        raise TimestampError("no OpenTimestamps calendar accepted the digest")
    return out
