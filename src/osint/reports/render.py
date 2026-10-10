"""Render a report: citation markers become footnotes carrying the full provenance.

[E:n] -> footnote with the verbatim quote, source URL, platform post time, capture time,
         SHA-256, Admiralty source grade and archive link
[F:n] -> footnote with the finding, its epistemic status/confidence and its own evidence
"""

from __future__ import annotations

import html
from pathlib import Path

import markdown as md
from sqlalchemy import select
from sqlalchemy.orm import Session

from osint.reports.verify import MARKER
from osint.storage.db import Artifact, Capture, EvidenceLink, Finding, Report

CSS = """
body{font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;max-width:860px;margin:2rem auto;
padding:0 1rem;color:#1d1d1f;background:#fff}
h1,h2,h3{line-height:1.25} table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ddd;padding:.4rem;vertical-align:top}
.footnote{font-size:.85rem;color:#444} .footnote li{margin:.35rem 0}
.status{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.8rem;
background:#eef;border:1px solid #ccd} code{font-size:.8rem}
@media (prefers-color-scheme: dark){body{background:#151517;color:#e6e6e6}
td,th{border-color:#333}.footnote{color:#aaa}.status{background:#223;border-color:#335}}
"""


def _evidence_note(s: Session, eid: int) -> str:
    row = s.execute(select(EvidenceLink, Artifact).join(Artifact, Artifact.id == EvidenceLink.artifact_id)
                    .where(EvidenceLink.id == eid)).first()
    if row is None:
        return "UNRESOLVED CITATION"
    ev, art = row
    from osint.storage.db import CitationRetraction

    if (cr := s.get(CitationRetraction, ev.id)) is not None:
        return f"RETRACTED CITATION E:{ev.id}: {cr.reason}"
    from osint.evidence.sources import credibility, grade_of

    grade = grade_of(s, art.source_id) + credibility(s, ev.target_type, ev.target_id)
    archive = s.scalar(select(Capture.external_url).where(
        Capture.artifact_id == art.id, Capture.kind == "archive_org").limit(1))
    parts = [f"“{ev.quote_original or ev.media_locator}”"]
    if ev.quote_translated:
        parts.append(f"(translation: “{ev.quote_translated}”, {ev.translator})")
    url = art.final_url or art.url or ""
    parts.append(f"Source: <{url}>" if url.startswith("http") else f"Source: {url}")
    if art.posted_at:
        parts.append(f"posted {art.posted_at:%Y-%m-%d %H:%M}Z")
    parts.append(f"captured {art.fetched_at_utc:%Y-%m-%d %H:%M}Z")
    parts.append(f"SHA-256 `{art.sha256}`")
    parts.append(f"Admiralty {grade}")
    if archive:
        parts.append(f"archive: <{archive}>")
    parts.append(f"evidence E:{ev.id}, artifact A:{art.id}")
    return " · ".join(parts)


def _finding_note(s: Session, fid: int) -> str:
    f = s.get(Finding, fid)
    if f is None:
        return "UNRESOLVED FINDING"
    evs = s.scalars(select(EvidenceLink.id).where(EvidenceLink.target_type == "finding",
                                                  EvidenceLink.target_id == fid)).all()
    tail = f" Evidence: {', '.join(f'E:{e}' for e in evs)}." if evs else ""
    return (f"Finding F:{f.id} ({f.epistemic_status}, confidence {f.confidence:.2f}, "
            f"by {f.created_by}): {f.text}{tail}")


def to_footnoted_markdown(s: Session, report: Report) -> str:
    used: list[str] = []

    def repl(m) -> str:
        label = f"{m.group(1)}{m.group(2)}"
        if label not in used:
            used.append(label)
        return f"[^{label}]"

    body = MARKER.sub(repl, report.markdown)
    notes = []
    for label in used:
        kind, num = label[0], int(label[1:])
        text = _evidence_note(s, num) if kind == "E" else _finding_note(s, num)
        notes.append(f"[^{label}]: {text}")
    v = report.verification or {}
    header = (f"> Report R:{report.id} · status **{report.status}** · "
              f"citation check: {v.get('summary', 'not run')}\n")
    if report.status == "overridden":
        header += f"> Verification overridden by {report.override_by}: {report.override_reason}\n"
    return header + "\n" + body.rstrip() + "\n\n" + "\n".join(notes) + "\n"


def to_html(markdown_text: str, title: str) -> str:
    body = md.markdown(markdown_text, extensions=["footnotes", "tables", "sane_lists"],
                       extension_configs={"footnotes": {"BACKLINK_TEXT": "↩"}})
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body>{body}</body></html>")


def render_report(s: Session, report: Report, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"report-{report.id}"
    text = to_footnoted_markdown(s, report)
    md_path = out_dir / f"{stem}.md"
    html_path = out_dir / f"{stem}.html"
    md_path.write_text(text, encoding="utf-8")
    html_path.write_text(to_html(text, report.title), encoding="utf-8")
    return {"md": md_path, "html": html_path}
