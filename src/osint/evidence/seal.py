"""Seal the custody chain: Merkle manifest -> Ed25519 signature -> trusted timestamps.

Each manifest covers the custody entries since the previous one. It records the chain
head (the last entry_hash, which commits to the whole history), a Merkle root over the
covered entry hashes (for short inclusion proofs in exported bundles), and the previous
manifest's root, so manifests form a chain too. Its SHA-256 digest is signed with
the installation key and timestamped (RFC 3161 + OpenTimestamps).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy import select

from osint.core.config import project_home
from osint.core.context import App
from osint.evidence import merkle
from osint.evidence.custody import canonical_json, compute_entry_hash
from osint.evidence.timestamp import (
    TimestampError,
    stamp_opentimestamps,
    stamp_rfc3161,
)
from osint.storage.db import CustodyLog, Manifest, TimestampProof

KEY_DIR = Path("config/keys")


# --------------------------------------------------------------------------- keys


def key_paths() -> tuple[Path, Path]:
    d = project_home() / KEY_DIR
    return d / "signing_ed25519.pem", d / "signing_ed25519.pub.pem"


def load_or_create_key() -> tuple[Ed25519PrivateKey, str, bytes]:
    """(private key, key id, public key PEM). The private key never leaves config/keys/."""
    priv_path, pub_path = key_paths()
    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        priv_path.parent.mkdir(parents=True, exist_ok=True)
        priv = Ed25519PrivateKey.generate()
        priv_path.write_bytes(priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    pub_pem = priv.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_path.write_bytes(pub_pem)
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return priv, hashlib.sha256(raw).hexdigest()[:16], pub_pem


def verify_signature(pub_pem: bytes, digest: bytes, signature_hex: str) -> bool:
    pub = serialization.load_pem_public_key(pub_pem)
    assert isinstance(pub, Ed25519PublicKey)
    try:
        pub.verify(bytes.fromhex(signature_hex), digest)
        return True
    except Exception:  # noqa: BLE001 - InvalidSignature and malformed input alike
        return False


# --------------------------------------------------------------------------- sealing


def manifest_digest(body: dict) -> bytes:
    return hashlib.sha256(canonical_json(body).encode("utf-8")).digest()


@dataclass
class SealResult:
    manifest_id: int
    entries: int
    merkle_root: str
    path: Path
    timestamps: list[str]
    errors: list[str]


def seal(app: App) -> SealResult | None:
    priv, key_id, pub_pem = load_or_create_key()
    with app.session_factory() as s, s.begin():
        prev = s.scalar(select(Manifest).order_by(Manifest.id.desc()).limit(1))
        after = prev.last_custody_seq if prev else 0
        entries = s.execute(select(CustodyLog.seq, CustodyLog.entry_hash).where(
            CustodyLog.seq > after).order_by(CustodyLog.seq)).all()
        if not entries:
            return None
        hashes = [h for _, h in entries]
        body = {
            "version": 1,
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "custody_from_seq": entries[0][0],
            "custody_to_seq": entries[-1][0],
            "leaf_count": len(hashes),
            "chain_head": hashes[-1],
            "merkle_root": merkle.root(hashes),
            "prev_manifest_root": prev.merkle_root if prev else None,
            "hash": "sha256", "merkle": "rfc6962-style (0x00 leaf, 0x01 node)",
        }
        digest = manifest_digest(body)
        signature = priv.sign(digest).hex()
        out_dir = app.settings.data_path / "manifests"
        out_dir.mkdir(parents=True, exist_ok=True)
        m = Manifest(merkle_root=body["merkle_root"], leaf_count=len(hashes),
                     first_custody_seq=entries[0][0], last_custody_seq=entries[-1][0],
                     path="", signature=signature, signer_key_id=key_id)
        s.add(m)
        s.flush()
        path = out_dir / f"manifest-{m.id:06d}.json"
        path.write_text(json.dumps({"manifest": body, "digest_sha256": digest.hex(),
                                    "signature_ed25519": signature, "key_id": key_id,
                                    "public_key_pem": pub_pem.decode()}, indent=2),
                        encoding="utf-8")
        m.path = path.relative_to(app.settings.data_path).as_posix()
        mid = m.id
    stamps, errors = asyncio.run(_timestamp(app, mid, digest)) \
        if app.settings.evidence.timestamp_methods else ([], [])
    return SealResult(mid, len(hashes), body["merkle_root"], path, stamps, errors)


async def _timestamp(app: App, manifest_id: int, digest: bytes) -> tuple[list[str], list[str]]:
    ev = app.settings.evidence
    done, errors = [], []
    out_dir = app.settings.data_path / "manifests"
    async with httpx.AsyncClient(timeout=30, proxy=app.settings.network.proxy) as client:
        results = []
        if "rfc3161" in ev.timestamp_methods:
            try:
                results.append(await stamp_rfc3161(digest, client, ev.tsa_url))
            except (TimestampError, httpx.HTTPError) as e:
                errors.append(f"rfc3161: {e}")
        if "opentimestamps" in ev.timestamp_methods:
            try:
                results += await stamp_opentimestamps(digest, client)
            except (TimestampError, httpx.HTTPError) as e:
                errors.append(f"opentimestamps: {e}")
    with app.session_factory() as s, s.begin():
        for i, r in enumerate(results):
            ext = "tsr" if r.method == "rfc3161" else f"{i}.ots"
            p = out_dir / f"manifest-{manifest_id:06d}.{ext}"
            p.write_bytes(r.proof)
            for name, data in r.extra_files.items():
                (out_dir / f"tsa-{name}").write_bytes(data)
            s.add(TimestampProof(manifest_id=manifest_id, method=r.method, authority=r.authority,
                                 proof_path=p.relative_to(app.settings.data_path).as_posix(),
                                 stamped_at=datetime.now(UTC), status=r.status))
            done.append(f"{r.method}@{r.authority} ({r.status})")
    return done, errors


# --------------------------------------------------------------------------- verification


@dataclass
class ManifestCheck:
    manifest_id: int
    ok: bool
    problems: list[str]


def verify_manifests(app: App) -> list[ManifestCheck]:
    out = []
    with app.session_factory() as s:
        prev_root = None
        for m in s.scalars(select(Manifest).order_by(Manifest.id)):
            problems = []
            path = app.settings.data_path / m.path
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                out.append(ManifestCheck(m.id, False, ["manifest file missing/unreadable"]))
                continue
            body = doc["manifest"]
            digest = manifest_digest(body)
            if digest.hex() != doc["digest_sha256"]:
                problems.append("manifest digest mismatch (file edited)")
            if not verify_signature(doc["public_key_pem"].encode(), digest,
                                    doc["signature_ed25519"]):
                problems.append("signature invalid")
            rows = s.scalars(select(CustodyLog).where(
                CustodyLog.seq >= m.first_custody_seq, CustodyLog.seq <= m.last_custody_seq)
                .order_by(CustodyLog.seq)).all()
            # recompute every hash from the entry's fields: a stored hash proves nothing if
            # the fields next to it were edited
            hashes = [compute_entry_hash(r.prev_hash, r.artifact_id, r.action, r.actor,
                                         r.at_utc, r.details) for r in rows]
            altered = [r.seq for r, h in zip(rows, hashes, strict=True) if h != r.entry_hash]
            if altered:
                problems.append(f"custody entries altered after sealing: seq {altered[:10]}")
            if len(hashes) != m.leaf_count or merkle.root(hashes) != body["merkle_root"]:
                problems.append("custody entries no longer match the sealed Merkle root")
            if body.get("prev_manifest_root") != prev_root:
                problems.append("manifest chain broken (prev_manifest_root)")
            prev_root = body["merkle_root"]
            for tp in s.scalars(select(TimestampProof).where(TimestampProof.manifest_id == m.id)):
                p = app.settings.data_path / tp.proof_path
                if not p.exists():
                    problems.append(f"{tp.method} proof file missing")
                elif digest not in p.read_bytes():
                    problems.append(f"{tp.method} proof does not commit to this manifest")
            out.append(ManifestCheck(m.id, not problems, problems))
    return out
