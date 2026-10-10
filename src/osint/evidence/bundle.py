"""Evidence bundles: a self-contained, independently verifiable export.

Contents (zip):
  report/                 the report (Markdown + HTML), if one is given
  evidence/A<id>/...      the cited artifacts: raw file, WARC, screenshot, PDF, DOM
  manifests/              the sealed manifests covering their custody entries, plus
                          timestamp proofs (RFC 3161 token + TSA certs, .ots files)
  bundle.json             file hashes, artifact metadata, custody entries with Merkle
                          inclusion proofs
  verify.py               standalone verifier (stdlib only)

Only *cited* evidence is included when a report is given (need-to-know), otherwise all
artifacts of the investigation. --exclude-kinds drops e.g. screenshots that show
uninvolved people. Excluded files are listed, so their absence is explicit.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select

from osint.core.context import App
from osint.evidence import merkle
from osint.evidence.custody import _ts
from osint.evidence.seal import seal
from osint.reports.render import render_report
from osint.storage.db import (
    Artifact,
    Capture,
    CustodyLog,
    EvidenceLink,
    Investigation,
    InvestigationRef,
    Manifest,
    Report,
    TimestampProof,
)

MARKER = re.compile(r"\[(E|F):(\d+)\]")
EXT = {"raw": "bin", "warc": "warc.gz", "screenshot_png": "png", "pdf_render": "pdf",
       "rendered_html": "html", "media_original": "bin"}


def _artifact_ids(s, inv_id: int, report: Report | None) -> list[int]:
    if report is None:
        return sorted(s.scalars(select(InvestigationRef.object_id).where(
            InvestigationRef.investigation_id == inv_id,
            InvestigationRef.object_type == "artifact")))
    ev_ids, f_ids = set(), set()
    for kind, num in MARKER.findall(report.markdown):
        (ev_ids if kind == "E" else f_ids).add(int(num))
    q = select(EvidenceLink.artifact_id).where(
        (EvidenceLink.id.in_(ev_ids))
        | ((EvidenceLink.target_type == "finding") & EvidenceLink.target_id.in_(f_ids)))
    return sorted(set(s.scalars(q)))


def build_bundle(app: App, inv_id: int, report_id: int | None = None,
                 exclude_kinds: tuple[str, ...] = (), redact_faces: bool = False) -> Path:
    seal(app)  # make sure every custody entry is covered by a manifest
    data = app.settings.data_path
    with app.session_factory() as s:
        inv = s.get(Investigation, inv_id)
        report = s.get(Report, report_id) if report_id else None
        if report is not None and report.investigation_id != inv_id:
            raise ValueError("report belongs to another investigation")
        art_ids = _artifact_ids(s, inv_id, report)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        out = data / "exports" / f"bundle-inv{inv_id}-{'r' + str(report_id) if report_id else 'all'}-{stamp}.zip"
        out.parent.mkdir(parents=True, exist_ok=True)

        files: dict[str, str] = {}
        excluded: list[dict] = []
        artifacts, custody = [], []
        manifest_rows = {m.id: m for m in s.scalars(select(Manifest))}
        mf_hashes: dict[int, list[str]] = {}
        mf_seqs: dict[int, list[int]] = {}

        def manifest_for(seq: int) -> Manifest | None:
            for m in manifest_rows.values():
                if m.first_custody_seq <= seq <= m.last_custody_seq:
                    return m
            return None

        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            def add(path: Path, arc: str) -> None:
                z.write(path, arc)
                files[arc] = hashlib.sha256(path.read_bytes()).hexdigest()

            def add_bytes(data_: bytes, arc: str) -> str:
                z.writestr(arc, data_)
                files[arc] = hashlib.sha256(data_).hexdigest()
                return files[arc]

            if report is not None:
                paths = render_report(s, report, data / "reports" / f"inv-{inv_id}")
                for p in paths.values():
                    add(p, f"report/{p.name}")

            for aid in art_ids:
                art = s.get(Artifact, aid)
                raw_arc = f"evidence/A{aid}/raw-{art.sha256[:12]}.{EXT['raw']}"
                add(data / art.path, raw_arc)
                caps = []
                for c in s.scalars(select(Capture).where(Capture.artifact_id == aid,
                                                         Capture.kind != "raw")):
                    if c.kind in exclude_kinds or not c.path:
                        excluded.append({"artifact": aid, "kind": c.kind, "sha256": c.sha256,
                                         "reason": "excluded by exporter" if c.path else
                                                   "external"})
                        continue
                    if redact_faces and c.kind in ("pdf_render", "rendered_html", "media_original"):
                        excluded.append({"artifact": aid, "kind": c.kind, "sha256": c.sha256,
                                         "reason": "may show people and can't be face-redacted"})
                        continue
                    if redact_faces and c.kind == "screenshot_png":
                        from osint.evidence.redact import METHOD, model_path
                        from osint.evidence.redact import redact_faces as blur

                        model = model_path(data / "models", app.settings.network.proxy)
                        red = blur((data / c.path).read_bytes(), model)
                        arc = f"evidence/A{aid}/screenshot_png-REDACTED-{c.sha256[:12]}.png"
                        caps.append({"kind": c.kind, "path": arc, "sha256": add_bytes(red.data, arc),
                                     "redacted_from": c.sha256,
                                     "redaction": {"method": METHOD, "regions": red.regions}})
                        continue
                    arc = f"evidence/A{aid}/{c.kind}-{c.sha256[:12]}.{EXT.get(c.kind, 'bin')}"
                    add(data / c.path, arc)
                    caps.append({"kind": c.kind, "path": arc, "sha256": c.sha256})
                artifacts.append({"id": aid, "url": art.url, "final_url": art.final_url,
                                  "sha256": art.sha256, "sha512": art.sha512,
                                  "fetched_at_utc": art.fetched_at_utc.isoformat(),
                                  "posted_at": art.posted_at.isoformat() if art.posted_at else None,
                                  "platform_id": art.platform_id, "raw_path": raw_arc,
                                  "captures": caps})
                for e in s.scalars(select(CustodyLog).where(CustodyLog.artifact_id == aid)
                                   .order_by(CustodyLog.seq)):
                    m = manifest_for(e.seq)
                    inclusion = None
                    if m is not None:
                        if m.id not in mf_hashes:
                            rows = s.execute(select(CustodyLog.seq, CustodyLog.entry_hash).where(
                                CustodyLog.seq >= m.first_custody_seq,
                                CustodyLog.seq <= m.last_custody_seq)
                                .order_by(CustodyLog.seq)).all()
                            mf_seqs[m.id] = [q for q, _ in rows]
                            mf_hashes[m.id] = [h for _, h in rows]
                        # position in the sealed list, NOT seq - first: sequences have gaps
                        # wherever a transaction rolled back
                        idx = mf_seqs[m.id].index(e.seq)
                        inclusion = {"manifest_id": m.id,
                                     "path": merkle.proof(mf_hashes[m.id], idx)}
                    custody.append({"seq": e.seq, "artifact_id": e.artifact_id,
                                    "action": e.action, "actor": e.actor, "at_utc": _ts(e.at_utc),
                                    "details": e.details, "prev_hash": e.prev_hash,
                                    "entry_hash": e.entry_hash, "inclusion": inclusion})

            manifests = []
            certs_added: dict[str, str] = {}
            for mid in sorted(mf_hashes):
                m = manifest_rows[mid]
                arc = f"manifests/{Path(m.path).name}"
                add(data / m.path, arc)
                stamps = []
                for tp in s.scalars(select(TimestampProof).where(TimestampProof.manifest_id == mid)):
                    tarc = f"manifests/{Path(tp.proof_path).name}"
                    add(data / tp.proof_path, tarc)
                    entry = {"method": tp.method, "authority": tp.authority, "path": tarc,
                             "status": tp.status}
                    if tp.method == "rfc3161":
                        for key, name in (("cacert", "tsa-cacert.pem"), ("tsacert", "tsa-tsa.crt")):
                            src = data / "manifests" / name
                            if src.exists():
                                if name not in certs_added:
                                    add(src, f"manifests/{name}")
                                    certs_added[name] = name
                                entry[key] = f"manifests/{name}"
                    stamps.append(entry)
                manifests.append({"id": mid, "path": arc, "timestamps": stamps})

            verifier = Path(__file__).with_name("verify_bundle.py")
            z.write(verifier, "verify.py")
            meta = {
                "title": f"Evidence bundle: investigation {inv.name} (id {inv_id})"
                         + (f", report R:{report_id}" if report_id else ""),
                "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "investigation": {"id": inv_id, "name": inv.name},
                "report_id": report_id, "files": files, "excluded": excluded,
                "artifacts": artifacts, "custody": custody, "manifests": manifests,
                "note": "Custody entries cover only the included artifacts; their Merkle "
                        "proofs show they belong to sealed, signed, timestamped manifests."
                        + (" Screenshots are face-redacted copies: each lists the SHA-256 of "
                           "the original it was derived from (the original is kept, unshared). "
                           "Automatic detection misses some faces; review before sharing."
                           if redact_faces else ""),
                "redacted": redact_faces,
            }
            z.writestr("bundle.json", json.dumps(meta, indent=2, ensure_ascii=False))
    return out
