"""osint command-line interface."""

from __future__ import annotations

import mimetypes
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import func, select, text

from osint.core.config import get_models_config, get_settings, project_home
from osint.core.context import App
from osint.core.models import CaptureMeta

# Windows consoles default to cp1252; evidence quotes and status marks need UTF-8.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

app = typer.Typer(no_args_is_help=True, help="Agent-based OSINT system.")
evidence_app = typer.Typer(no_args_is_help=True, help="Evidence store and custody chain.")
app.add_typer(evidence_app, name="evidence")
console = Console()


def _alembic_config():
    from alembic.config import Config

    cfg = Config(str(project_home() / "alembic.ini"))
    cfg.attributes["skip_logging"] = False
    return cfg


# --------------------------------------------------------------------------- init / doctor


def _wait_for(name: str, probe, timeout: float) -> None:
    """Retry probe() until it succeeds. On a fresh volume, Postgres runs a temporary
    init server and then restarts, so the first connections can be dropped."""
    import time

    deadline = time.monotonic() + timeout
    with console.status(f"waiting for {name}..."):
        while True:
            try:
                probe()
                return
            except Exception as e:  # any failure means not ready yet
                if time.monotonic() >= deadline:
                    console.print(f"[red]✗[/] {name} not ready after {timeout:.0f}s: {e}")
                    raise typer.Exit(1) from e
                time.sleep(2)


@app.command()
def init(
    skip_graph: bool = typer.Option(False, help="Don't touch Neo4j."),
    wait: float = typer.Option(90, help="Seconds to wait for services to come up."),
) -> None:
    """Apply DB migrations, create Neo4j constraints and data directories."""
    from alembic import command

    from osint.storage.session import make_engine

    settings = get_settings()
    for sub in ("raw", "manifests", "exports", "reports"):
        (settings.data_path / sub).mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✓[/] data dir: {settings.data_path}")

    engine = make_engine(settings)

    def pg_probe() -> None:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))

    _wait_for("postgres", pg_probe, wait)
    engine.dispose()
    command.upgrade(_alembic_config(), "head")
    console.print("[green]✓[/] postgres schema at head")

    if not skip_graph:
        from osint.storage.graph import ensure_schema, make_driver

        with make_driver(settings) as driver:
            _wait_for("neo4j", driver.verify_connectivity, wait)
            ensure_schema(driver)
        console.print("[green]✓[/] neo4j constraints")


@app.command()
def doctor() -> None:
    """Check every dependency the system needs and report what's missing."""
    from osint.core.doctor import run_checks

    results = run_checks()
    t = Table(show_header=True, header_style="bold")
    t.add_column("component")
    t.add_column("status")
    t.add_column("detail", overflow="fold")
    for name, ok, detail in results:
        t.add_row(name, "[green]ok[/]" if ok else "[red]FAIL[/]", detail)
    console.print(t)
    if not all(ok for _, ok, _ in results):
        raise typer.Exit(1)


# --------------------------------------------------------------------------- introspection


@app.command()
def plugins(kind: Annotated[str | None, typer.Argument()] = None) -> None:
    """List discovered plugins."""
    t = Table("kind", "name", "version", "origin", "description")
    for cls, origin in App().registry.list(kind):
        t.add_row(cls.kind, cls.name, cls.version, origin, cls.description)
    console.print(t)


@app.command()
def ontology() -> None:
    """Show the merged ontology (base + plugin fragments)."""
    onto = App().ontology
    strong = onto.strong_identifier_types()
    for section in ("entity_types", "relation_types", "event_types"):
        t = Table(title=section, show_header=True)
        t.add_column("type")
        t.add_column("details", overflow="fold")
        for name, spec in getattr(onto, section).items():
            extra = " [cyan](strong id)[/]" if name in strong else ""
            t.add_row(name + extra, ", ".join(f"{k}={v}" for k, v in spec.items()))
        console.print(t)


# --------------------------------------------------------------------------- evidence


@evidence_app.command("add")
def evidence_add(
    path: Path,
    url: Annotated[str | None, typer.Option(help="Where the file came from.")] = None,
    actor: Annotated[str, typer.Option(help="Who is adding it.")] = "user:cli",
) -> None:
    """Ingest a local file as evidence (hashes, raw capture, custody entry)."""
    from osint.evidence.ingest import ingest_bytes

    a = App()
    with a.session_factory() as s, s.begin():
        art, created = ingest_bytes(
            s, a.raw_store, path.read_bytes(),
            CaptureMeta(url=url or path.resolve().as_uri(), collector=actor,
                        extra={"original_filename": path.name}),
            actor=actor, mime=mimetypes.guess_type(path.name)[0],
        )
    status = "stored" if created else "already stored (custody: observed_again)"
    console.print(f"artifact [bold]{art.id}[/] {status}\n  sha256 {art.sha256}\n  path   {art.path}")


@evidence_app.command("seal")
def evidence_seal() -> None:
    """Seal new custody entries: Merkle manifest, Ed25519 signature, trusted timestamps."""
    from osint.evidence.seal import seal

    r = seal(App())
    if r is None:
        console.print("nothing new to seal")
        return
    console.print(f"[green]✓[/] manifest {r.manifest_id}: {r.entries} custody entries, "
                  f"Merkle root {r.merkle_root[:16]}\u2026 \u2192 {r.path.name}")
    for t in r.timestamps:
        console.print(f"  timestamp: {t}")
    for e in r.errors:
        console.print(f"  [yellow]timestamp failed[/]: {e}")


@evidence_app.command("bundle")
def evidence_bundle(
    investigation: str,
    report_id: Annotated[int | None, typer.Option("--report", help="Only evidence this report cites.")] = None,
    exclude_kinds: Annotated[str, typer.Option(help="Comma list, e.g. screenshot_png,rendered_html")] = "",
    redact_faces: Annotated[bool, typer.Option(
        help="Blur faces in screenshots; drop PDF/DOM/media captures (needs --extra media).")] = False,
) -> None:
    """Export a self-contained, independently verifiable evidence bundle (zip + verify.py)."""
    from osint.evidence.bundle import build_bundle

    a = App()
    inv = _inv_id_or_none(a, investigation)
    kinds = tuple(k.strip() for k in exclude_kinds.split(",") if k.strip())
    out = build_bundle(a, inv, report_id, kinds, redact_faces)
    console.print(f"[green]✓[/] bundle: {out}\n  verify anywhere: unzip, then `python verify.py`")


@evidence_app.command("purge")
def evidence_purge(
    artifact_id: int,
    reason: Annotated[str, typer.Option("--reason", help="Recorded in the custody chain.")],
    yes: Annotated[bool, typer.Option("--yes", help="Don't ask for confirmation.")] = False,
) -> None:
    """Hard-delete an artifact's content (CSAM/malware procedure) and blocklist its hashes."""
    from osint.evidence.purge import delete_files, purge_artifact

    a = App()
    if not yes and not typer.confirm(f"Permanently delete the content of artifact {artifact_id}?"):
        raise typer.Exit(1)
    with a.session_factory() as s, s.begin():
        out = purge_artifact(s, a.raw_store, artifact_id, reason)
    deleted = delete_files(a.raw_store, out["files"])
    console.print(f"purged artifact {artifact_id}: {deleted} file(s) deleted, "
                  f"{out['documents']} document(s) and {out['evidence_links']} quote(s) blanked; "
                  f"{len(out['files'])} hash(es) blocklisted")


@evidence_app.command("blocklist")
def evidence_blocklist() -> None:
    """Show the loaded content blocklists (<data>/blocklists/*.txt)."""
    bl = App().raw_store.blocklist
    console.print(f"{len(bl)} blocked hash(es) from {bl.dir}")


@evidence_app.command("verify")
def evidence_verify() -> None:
    """Re-hash every artifact and capture, and verify the custody hash chain."""
    from osint.evidence.custody import verify_chain
    from osint.evidence.purge import purged_hashes
    from osint.storage.db import Artifact, Capture
    from osint.storage.raw_store import IntegrityError

    a = App()
    bad: list[str] = []
    n = 0
    with a.session_factory() as s:
        gone = purged_hashes(s)
        for sha256, sha512 in s.execute(select(Artifact.sha256, Artifact.sha512)).yield_per(500):
            if sha256 in gone:
                continue
            n += 1
            try:
                a.raw_store.verify(sha256, sha512)
            except IntegrityError as e:
                bad.append(str(e))
        for sha256, sha512 in s.execute(
            select(Capture.sha256, Capture.sha512).where(Capture.sha256.isnot(None))
        ).yield_per(500):
            if sha256 in gone:
                continue
            try:
                a.raw_store.verify(sha256, sha512)
            except IntegrityError as e:
                bad.append(f"capture: {e}")
        chain = verify_chain(s)

    console.print(f"artifacts checked: {n}, integrity problems: {len(bad)}")
    for b in bad[:50]:
        console.print(f"  [red]✗[/] {b}")
    if chain.ok:
        console.print(f"[green]✓[/] custody chain intact ({chain.entries} entries)")
    else:
        console.print(f"[red]✗ custody chain broken at seq {chain.first_bad_seq}: {chain.problem}[/]")
    from osint.evidence.seal import verify_manifests

    checks = verify_manifests(a)
    for c in checks:
        if c.ok:
            console.print(f"[green]✓[/] manifest {c.manifest_id}: digest, signature, Merkle root, "
                          "chain link, timestamp proofs")
        else:
            console.print(f"[red]✗ manifest {c.manifest_id}: {'; '.join(c.problems)}[/]")
    if not checks:
        console.print("[yellow]no sealed manifests yet[/] (run: osint evidence seal)")
    if bad or not chain.ok or any(not c.ok for c in checks):
        raise typer.Exit(1)


# --------------------------------------------------------------------------- investigations


def _find_investigation(s, ref: str):
    from osint.storage.db import Investigation

    inv = s.get(Investigation, int(ref)) if ref.isdigit() else None
    if inv is None:
        inv = s.scalar(select(Investigation).where(Investigation.name == ref))
    if inv is None:
        console.print(f"[red]no investigation {ref!r}[/] (see: osint status)")
        raise typer.Exit(1)
    return inv


@app.command()
def new(
    name: str,
    focus: Annotated[str | None, typer.Option(help="What this investigation is about.")] = None,
    query: Annotated[
        list[str] | None, typer.Option("--query", "-q", help="Search query (repeatable).")
    ] = None,
    url: Annotated[
        list[str] | None, typer.Option("--url", "-u", help="URL to capture (repeatable).")
    ] = None,
    feed: Annotated[
        list[str] | None, typer.Option("--feed", "-f", help="RSS/Atom feed (repeatable).")
    ] = None,
    lang: Annotated[str | None, typer.Option(help="Search language code, e.g. en, ar, ru. Default: all languages.")] = None,
    time_range: Annotated[str | None, typer.Option(help="day|week|month|year")] = None,
    max_results: Annotated[int, typer.Option(help="Results to fetch per query.")] = 10,
    max_fetches: Annotated[int, typer.Option(help="Cap on fetch tasks.")] = 200,
    run_now: Annotated[bool, typer.Option("--run", help="Start running immediately.")] = False,
    plan_first: Annotated[bool, typer.Option(
        "--plan", help="Let Claude plan multilingual collection from the focus.")] = False,
    anonymous: Annotated[bool, typer.Option(
        "--anonymous", help="All collection through Tor; never a direct connection.")] = False,
) -> None:
    """Create an investigation and queue its initial collection tasks."""
    from osint.orchestrator.investigations import InvestigationError, create_investigation

    try:
        inv_id, n_specs = create_investigation(
            App(), name, focus, query, url, feed, lang, time_range, max_results, max_fetches,
            anonymous, plan_first)
    except InvestigationError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None
    console.print(f"[green]✓[/] investigation [bold]{name}[/] (id {inv_id}), "
                  f"{n_specs} task(s) queued")
    if plan_first:
        plan(str(inv_id), max_requests=12, fresh=False, run_after=run_now)
        return
    if run_now:
        _run(str(inv_id))
    else:
        console.print(f"  next: uv run python -m osint run {inv_id}")


def _run(ref: str, force_reclaim: bool = False, retry_failed: bool = False,
         no_screenshots: bool = False, post: bool = True, extract_role: str | None = None) -> None:
    import asyncio
    import logging

    from osint.orchestrator import queue
    from osint.orchestrator.runner import Runner

    logging.basicConfig(level=logging.WARNING)
    a = App()
    if no_screenshots:
        a.settings.evidence.screenshots = False
    if extract_role:
        a.settings.extraction.llm_role = extract_role
    with a.session_factory() as s, s.begin():
        inv = _find_investigation(s, ref)
        inv_id, inv_name = inv.id, inv.name
        from osint.net.profile import apply_profile, profile_of

        profile = profile_of(inv)
        if force_reclaim and (n := queue.reclaim(s, inv_id, None)):
            console.print(f"reclaimed {n} running task(s)")
        if retry_failed and (n := queue.retry_failed(s, inv_id)):
            console.print(f"re-queued {n} failed/blocked task(s)")

    from osint.net.tor import TorUnavailable

    try:
        a.settings = apply_profile(a.settings, profile, inv_id)
    except TorUnavailable as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None

    async def go():
        async with a.services() as services:
            return await Runner(a, inv_id, services, on_event=console.print).run()

    route = " via Tor (anonymous profile)" if profile == "anonymous" else ""
    console.print(f"running [bold]{inv_name}[/]{route} (Ctrl+C to pause; resume later)")
    try:
        summary = asyncio.run(go())
    except KeyboardInterrupt:
        console.print("[yellow]paused[/]: in-flight tasks were released. "
                      f"Continue with: uv run python -m osint resume {inv_id}")
        raise typer.Exit(130) from None
    console.print(f"done in {summary.seconds:.0f}s: {summary.done} task(s) ok, "
                  f"{summary.retried} retried, {summary.failed} failed  {summary.by_type}")
    if post and summary.done:
        _post_run(a, inv_id)
    status(str(inv_id))


@app.command()
def run(
    investigation: str,
    no_screenshots: Annotated[bool, typer.Option(help="Skip Playwright capture.")] = False,
    extract_role: Annotated[str | None, typer.Option(
        help="Extraction model role for this run: agent (fast) | agent_heavy (accurate).")] = None,
) -> None:
    """Run an investigation's queued tasks until the queue is empty."""
    _run(investigation, no_screenshots=no_screenshots, extract_role=extract_role)


@app.command()
def resume(
    investigation: str,
    force: Annotated[
        bool, typer.Option(help="Reclaim running tasks now (no other runner is alive).")
    ] = True,
    retry_failed: Annotated[bool, typer.Option(help="Re-queue failed/blocked tasks.")] = False,
    no_screenshots: bool = False,
    extract_role: Annotated[str | None, typer.Option(
        help="Extraction model role: agent (fast) | agent_heavy (accurate).")] = None,
) -> None:
    """Continue a paused or crashed investigation from its checkpoints."""
    _run(investigation, force_reclaim=force, retry_failed=retry_failed,
         no_screenshots=no_screenshots, extract_role=extract_role)


@app.command()
def status(investigation: Annotated[str | None, typer.Argument()] = None) -> None:
    """List investigations, or show one investigation's queue and knowledge counts."""
    from osint.orchestrator import queue
    from osint.storage.db import Investigation, InvestigationRef, ReviewItem, Task

    a = App()
    with a.session_factory() as s:
        if investigation is None:
            t = Table("id", "name", "status", "open tasks", "created")
            for inv in s.scalars(select(Investigation).order_by(Investigation.id)):
                open_n = s.scalar(select(func.count()).where(
                    Task.investigation_id == inv.id, Task.status.in_(["pending", "running"])))
                t.add_row(str(inv.id), inv.name, inv.status, str(open_n),
                          inv.created_at.strftime("%Y-%m-%d %H:%M"))
            console.print(t)
            return
        inv = _find_investigation(s, investigation)
        counts = queue.counts(s, inv.id)
        statuses = ["pending", "running", "done", "failed", "blocked"]
        t = Table("type", *statuses, title=f"{inv.name} (id {inv.id}): tasks")
        for typ in sorted({k[0] for k in counts}):
            t.add_row(typ, *[str(counts.get((typ, st), "")) for st in statuses])
        console.print(t)
        refs = dict(s.execute(
            select(InvestigationRef.object_type, func.count())
            .where(InvestigationRef.investigation_id == inv.id)
            .group_by(InvestigationRef.object_type)).all())
        review_open = s.scalar(select(func.count()).where(
            ReviewItem.investigation_id == inv.id, ReviewItem.status == "open"))
        k = Table("artifacts", "documents", "entities", "relations", "events", "review open",
                  title="knowledge")
        k.add_row(*[str(refs.get(x, 0)) for x in
                    ("artifact", "document", "entity", "relation", "event")], str(review_open))
        console.print(k)
        for f in s.scalars(select(Task).where(Task.investigation_id == inv.id,
                                              Task.status == "failed").limit(5)):
            console.print(f"  [red]failed[/] #{f.id} {f.type}:{f.plugin} {(f.error or '')[:160]}")


@app.command()
def entity(
    query: str,
    investigation: Annotated[
        str | None, typer.Option("--in", help="Limit to one investigation.")
    ] = None,
    limit: int = 10,
) -> None:
    """Show matching entities with relations, events and citations (across investigations)."""
    from osint.storage.db import (
        Artifact,
        Entity,
        EntityAlias,
        Event,
        EventParticipant,
        EvidenceLink,
        InvestigationRef,
        Relation,
    )
    from osint.text.normalize import name_key

    a = App()
    with a.session_factory() as s:
        q = (select(Entity).join(EntityAlias, EntityAlias.entity_id == Entity.id)
             .where(EntityAlias.alias_norm.contains(name_key(query)),
                    Entity.merged_into_id.is_(None)).distinct().limit(limit))
        if investigation:
            inv = _find_investigation(s, investigation)
            q = q.join(InvestigationRef, (InvestigationRef.object_type == "entity")
                       & (InvestigationRef.object_id == Entity.id)
                       & (InvestigationRef.investigation_id == inv.id))
        ents = s.scalars(q).all()
        if not ents:
            console.print("no matching entities")
            return

        def cite(target_type: str, target_id: int) -> None:
            rows = s.execute(
                select(EvidenceLink, Artifact)
                .join(Artifact, Artifact.id == EvidenceLink.artifact_id)
                .where(EvidenceLink.target_type == target_type,
                       EvidenceLink.target_id == target_id).limit(3))
            for ev, art in rows:
                console.print(f"      [dim]\\[E:{ev.id}][/] “{ev.quote_original[:220]}”")
                console.print(f"      [dim]{art.final_url or art.url} · captured "
                              f"{art.fetched_at_utc:%Y-%m-%d %H:%M}Z · sha256 "
                              f"{art.sha256[:16]}…[/]")

        other = Entity.__table__.alias("other")
        for e in ents:
            aliases = s.scalars(select(EntityAlias.alias).where(EntityAlias.entity_id == e.id))
            invs = s.scalars(select(InvestigationRef.investigation_id).where(
                InvestigationRef.object_type == "entity", InvestigationRef.object_id == e.id))
            console.rule(f"[bold]{e.canonical_name}[/] ({e.type}, id {e.id})")
            console.print(f"aliases: {', '.join(sorted(set(aliases)))}   "
                          f"investigations: {sorted(invs)}")
            for r, oname in s.execute(
                select(Relation, other.c.canonical_name)
                .join(other, other.c.id == Relation.dst_entity_id)
                .where(Relation.src_entity_id == e.id)):
                console.print(f"  → {r.type} [bold]{oname}[/] (conf {r.confidence:.2f})")
                cite("relation", r.id)
            for r, oname in s.execute(
                select(Relation, other.c.canonical_name)
                .join(other, other.c.id == Relation.src_entity_id)
                .where(Relation.dst_entity_id == e.id)):
                console.print(f"  ← {r.type} from [bold]{oname}[/] (conf {r.confidence:.2f})")
                cite("relation", r.id)
            for ev, role in s.execute(
                select(Event, EventParticipant.role)
                .join(EventParticipant, EventParticipant.event_id == Event.id)
                .where(EventParticipant.entity_id == e.id).limit(10)):
                when = ev.time.strftime("%Y-%m-%d") if ev.time else "undated"
                console.print(f"  ● {ev.type} ({role}, {when}): {ev.description}")
                cite("event", ev.id)


def _recheck_reviews(a, investigation: str | None) -> None:
    from osint.core.models import ExtractedEvent, ExtractedRelation, ExtractionResult
    from osint.extraction.quotes import QuoteIndex
    from osint.extraction.writer import ExtractionWriter
    from osint.storage.db import Document, ReviewItem

    accepted = still = 0
    with a.session_factory() as s:
        q = select(ReviewItem).where(ReviewItem.status == "open",
                                     ReviewItem.kind == "quote_not_found")
        if investigation:
            q = q.where(ReviewItem.investigation_id == _find_investigation(s, investigation).id)
        ids = [r.id for r in s.scalars(q)]
    for rid in ids:
        with a.session_factory() as s, s.begin():
            r = s.get(ReviewItem, rid)
            doc = s.get(Document, r.document_id)
            p = r.payload
            if not doc or not p.get("quote") or QuoteIndex(doc.text).find(p["quote"]) is None:
                still += 1
                continue
            if r.reason.startswith("relation"):
                res = ExtractionResult(relations=[ExtractedRelation(**p)])
            elif r.reason.startswith("event"):
                res = ExtractionResult(events=[ExtractedEvent(**p)])
            else:
                still += 1
                continue
            w = ExtractionWriter(s, a.ontology, r.investigation_id, doc, actor="review:recheck")
            w.write(res)
            if w.stats.rejected == 0:
                w.finish("review:recheck")
                r.status = "accepted"
                accepted += 1
            else:
                still += 1
    console.print(f"recheck: {accepted} accepted and written, {still} still rejected")


@app.command()
def review(
    investigation: Annotated[str | None, typer.Argument()] = None,
    kind: Annotated[
        str | None,
        typer.Option(help="quote_not_found|ontology|resolution_candidate|unresolved"),
    ] = None,
    limit: int = 20,
    recheck: Annotated[bool, typer.Option(help="Re-verify rejected quotes (after verifier "
                                                "fixes) and write the ones that now pass.")] = False,
) -> None:
    """List open review items (rejected extractions, resolution candidates)."""
    from osint.storage.db import ReviewItem

    a = App()
    if recheck:
        _recheck_reviews(a, investigation)
    with a.session_factory() as s:
        q = select(ReviewItem).where(ReviewItem.status == "open").order_by(ReviewItem.id.desc())
        if investigation:
            q = q.where(ReviewItem.investigation_id == _find_investigation(s, investigation).id)
        if kind:
            q = q.where(ReviewItem.kind == kind)
        counts = dict(s.execute(select(ReviewItem.kind, func.count()).where(
            ReviewItem.status == "open").group_by(ReviewItem.kind)).all())
        console.print("open: " + (", ".join(f"{k}={v}" for k, v in counts.items()) or "none"))
        t = Table("id", "kind", "reason", "payload")
        for r in s.scalars(q.limit(limit)):
            t.add_row(str(r.id), r.kind, r.reason[:60], str(r.payload)[:120])
        console.print(t)


# --------------------------------------------------------------------------- analyst (Claude)


def _analyst():
    from osint.analyst.jobs import Analyst

    return Analyst(App())


def _claude_call(fn, *args, **kwargs):
    from osint.llm.claude_cli import ClaudeJobError, QuotaExceeded

    try:
        return fn(*args, **kwargs)
    except QuotaExceeded as e:
        console.print(f"[yellow]Claude usage limit reached[/]: {e}\n"
                      "Local collection keeps working; re-run this command later.")
        raise typer.Exit(75) from None
    except ClaudeJobError as e:
        console.print(f"[red]Claude job failed[/]: {e}")
        raise typer.Exit(1) from None


def _job_footer(res) -> None:
    if res.cached:
        console.print(f"[dim](cached result of job #{res.job_id}; knowledge unchanged; "
                      "use --fresh to re-run)[/]")
    else:
        console.print(f"[dim]job #{res.job_id}: {res.num_turns} turns, "
                      f"{res.input_tokens or 0:,} in / {res.output_tokens or 0:,} out tokens, "
                      f"{(res.duration_ms or 0) / 1000:.0f}s[/]")


@app.command()
def plan(
    investigation: str,
    max_requests: Annotated[int, typer.Option(help="Collection requests Claude may queue.")] = 12,
    fresh: bool = False,
    run_after: Annotated[bool, typer.Option("--run", help="Run the queued collection.")] = False,
) -> None:
    """Claude plans the collection: key questions and multilingual searches/sources."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    out = _claude_call(_analyst().plan, inv_id, max_requests=max_requests, fresh=fresh)
    p = out.extra.get("plan") or {}
    for q in p.get("questions", []):
        console.print(f"  ? {q}")
    for c in p.get("collection", []):
        console.print(f"  + task {c.get('task_id')}: {c.get('plugin')}: {c.get('why', '')}")
    _job_footer(out.result)
    if run_after:
        _run(str(inv_id))
    else:
        console.print(f"  next: uv run python -m osint run {inv_id}")


@app.command()
def analyze(
    investigation: str,
    max_requests: Annotated[int, typer.Option(help="Follow-up collection requests.")] = 10,
    fresh: bool = False,
) -> None:
    """Claude analyses the knowledge base and records findings with proof."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    out = _claude_call(_analyst().analyze, inv_id, max_requests=max_requests, fresh=fresh)
    data = out.result.data or {}
    console.print(out.result.text if not data else "")
    for q, a in (data.get("answered_questions") or {}).items():
        console.print(f"  [bold]{q}[/]\n    {a}")
    if data.get("open_questions"):
        console.print("  open: " + "; ".join(data["open_questions"]))
    console.print(f"  findings: {', '.join(data.get('findings', [])) or 'see `osint findings`'}")
    if data.get("collection_requested"):
        console.print(f"  follow-up collection queued: {data['collection_requested']} "
                      f"(run: uv run python -m osint run {inv_id})")
    _job_footer(out.result)


@app.command()
def report(
    investigation: str,
    audience: str = "security analysts and decision makers",
    no_audit: Annotated[bool, typer.Option(help="Skip the automatic citation audit.")] = False,
    fresh: bool = False,
) -> None:
    """Claude writes the report; the citation gate verifies it; render MD + HTML."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    analyst = _analyst()
    if not analyst.red_team_current(inv_id):
        console.print("[yellow]note:[/] no red-team pass since the latest analysis; consider "
                      f"`osint red-team {investigation}` before a final report")
    out = _claude_call(analyst.report, inv_id, audience=audience, audit=not no_audit,
                       fresh=fresh)
    x = out.extra
    if not x.get("report_id"):
        console.print("[red]no report was written[/]")
        console.print(out.result.text[-2000:])
        raise typer.Exit(1)
    color = "green" if x["status"] == "verified" else "yellow"
    console.print(f"report R:{x['report_id']} [{color}]{x['status']}[/] "
                  f"({x.get('verification')}), audits: {x['audits']}")
    for k, v in x["paths"].items():
        console.print(f"  {k}: {v}")
    if x["status"] != "verified":
        console.print(f"  details: uv run python -m osint report-verify {x['report_id']}")
    _job_footer(out.result)


@app.command("red-team")
def red_team_cmd(
    investigation: str,
    max_requests: Annotated[int, typer.Option(help="Discriminating collection requests.")] = 5,
    fresh: bool = False,
) -> None:
    """Claude challenges the findings: ACH, alternative hypotheses, gaps, downgrades."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    out = _claude_call(_analyst().red_team, inv_id, max_requests=max_requests, fresh=fresh)
    if out.result is None:
        console.print(out.extra.get("skipped"))
        return
    d = out.result.data or {}
    console.print(f"verdict: [bold]{d.get('verdict', '?')}[/]")
    for c in d.get("challenged", []):
        console.print(f"  {c.get('finding')}: {c.get('issue')} "
                      f"(suggested confidence {c.get('suggested_confidence')})")
    if d.get("alternative_hypotheses"):
        console.print(f"  alternative hypotheses: {' '.join(d['alternative_hypotheses'])}")
    if d.get("gaps"):
        console.print(f"  gaps: {' '.join(d['gaps'])}")
    for r in out.extra.get("revisions", []):
        console.print(f"  revision: {r}")
    _job_footer(out.result)


@app.command("apply-red-team")
def apply_red_team_cmd(job_id: int) -> None:
    """Apply a past red-team job's suggested confidences (downgrades apply, rest to review)."""
    for r in _analyst().apply_red_team(job_id):
        console.print(r)


@app.command()
def assess(investigation: str, fresh: bool = False) -> None:
    """Claude threat assessment: capability, intent, opportunity, likelihood, indicators."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    out = _claude_call(_analyst().threat_assessment, inv_id, fresh=fresh)
    d = out.result.data or {}
    for a in d.get("actors", []):
        console.print(f"  [bold]{a.get('name')}[/]: {a.get('threat_level')} "
                      f"({a.get('confidence')} confidence) {' '.join(a.get('findings', []))}")
    if d.get("summary"):
        console.print(d["summary"])
    console.print("  next: osint red-team, then osint report")
    _job_footer(out.result)


@app.command("report-verify")
def report_verify(
    report_id: int,
    no_judge: Annotated[bool, typer.Option(help="Skip the LLM support check.")] = False,
) -> None:
    """Re-run the citation gate on a report and show every problem sentence."""
    import asyncio

    from osint.analyst.tools import AnalystTools
    from osint.storage.db import Report

    a = App()
    with a.session_factory() as s:
        r = s.get(Report, report_id)
        if r is None:
            console.print(f"[red]no report {report_id}[/]")
            raise typer.Exit(1)
        inv_id = r.investigation_id

    async def go():
        judge, llm = None, None
        if not no_judge:
            from osint.llm.local import LocalLLM
            from osint.reports.verify import llm_judge

            llm = LocalLLM(get_models_config().local, slots=a.settings.concurrency.llm_slots)
            judge = llm_judge(llm)
        try:
            tools = AnalystTools(a.session_factory, a.ontology, a.registry, a.raw_store, inv_id,
                                 actor="user:cli", judge=judge)
            return await tools.verify_report(report_id)
        finally:
            if llm is not None:
                await llm.aclose()

    res = asyncio.run(go())
    console.print(("[green]" if res["ok"] else "[red]") + res["summary"] + "[/]")
    for i in res["issues"]:
        console.print(f"  #{i['sentence']} {', '.join(i['issues'])}: {i['text'][:200]}")
        if i.get("missing"):
            console.print(f"      missing: {i['missing']}")


@app.command("report-override")
def report_override(
    report_id: int,
    reason: Annotated[str, typer.Option(help="Why the report is released despite the gate.")],
    by: Annotated[str, typer.Option(help="Who decides.")] = "user:cli",
) -> None:
    """Release a report that failed the citation gate (the override is recorded on it)."""
    from osint.storage.db import Report

    with App().session_factory() as s, s.begin():
        r = s.get(Report, report_id)
        if r is None:
            console.print(f"[red]no report {report_id}[/]")
            raise typer.Exit(1)
        r.status, r.override_by, r.override_reason = "overridden", by, reason
    console.print(f"report R:{report_id} overridden by {by}; re-render with: "
                  f"uv run python -m osint report-render {report_id}")


@app.command("report-render")
def report_render(report_id: int) -> None:
    """Render a report to Markdown + HTML with provenance footnotes."""
    paths = _analyst().render(report_id)
    for k, v in paths.items():
        console.print(f"{k}: {v}")


@app.command()
def ask(investigation: str, question: str) -> None:
    """Ask Claude a question; answered from the knowledge base with citations (read-only)."""
    with App().session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    out = _claude_call(_analyst().ask, inv_id, question)
    text = out.result.text
    cut = text.rfind("```json")
    console.print(text[:cut].rstrip() if cut > 0 else text)
    _job_footer(out.result)


@app.command()
def findings(investigation: str) -> None:
    """List recorded findings with their epistemic status and evidence."""
    from osint.analyst.tools import AnalystTools

    a = App()
    with a.session_factory() as s:
        inv_id = _find_investigation(s, investigation).id
    tools = AnalystTools(a.session_factory, a.ontology, a.registry, a.raw_store, inv_id)
    rows = tools.list_findings(inv_id)
    if not rows:
        console.print("no findings yet (run: osint analyze)")
    for f in rows:
        gone = " [red]WITHDRAWN[/]" if f.get("status") == "withdrawn" else ""
        console.print(f"{f['marker']} [bold]{f['kind']}[/] ({f['epistemic_status']}, "
                      f"{f['confidence']:.2f}){gone} {f['text']}")
        for r in f.get("revisions", [])[:2]:
            console.print(f"      [dim]revision {r['from']:.2f} -> {r['to']:.2f} ({r['status']}, "
                          f"{r['by']}): {r['reason'][:120]}[/]")
        if f["evidence"]:
            console.print(f"      evidence: {' '.join(f['evidence'])}")


@app.command()
def revise(
    finding_id: int,
    reason: Annotated[str, typer.Option(help="What evidence changes it.")],
    confidence: Annotated[float | None, typer.Option(help="New confidence 0-1.")] = None,
    withdraw: Annotated[bool, typer.Option(help="Withdraw the finding (shown wrong).")] = False,
    evidence: Annotated[str, typer.Option(help="Comma list of evidence ids.")] = "",
    by: str = "human:cli",
) -> None:
    """Revise a finding's confidence or withdraw it (history kept; applied immediately)."""
    from osint.analyst.revisions import RevisionError, propose_revision
    from osint.storage.db import Finding

    a = App()
    try:
        with a.session_factory() as s, s.begin():
            f = s.get(Finding, finding_id)
            if f is None:
                raise RevisionError(f"no finding {finding_id}")
            new = 0.0 if withdraw else (confidence if confidence is not None else f.confidence)
            ev = [int(x) for x in evidence.split(",") if x.strip()]
            console.print(propose_revision(s, finding_id, new, reason, by, ev, withdraw))
    except RevisionError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None


@app.command()
def explain(finding_id: int, depth: int = 4) -> None:
    """Show a finding's proof tree, down to the preserved quotes and their sources."""
    from osint.storage.db import (
        Artifact,
        EvidenceLink,
        Finding,
        Inference,
        InferencePremise,
        Relation,
    )
    from osint.storage.db import Event as EventRow

    a = App()
    with a.session_factory() as s:

        def evidence_line(ev_id: int, pad: str) -> None:
            row = s.execute(select(EvidenceLink, Artifact).join(
                Artifact, Artifact.id == EvidenceLink.artifact_id)
                .where(EvidenceLink.id == ev_id)).first()
            if row is None:
                console.print(f"{pad}[red]E:{ev_id} missing[/]")
                return
            ev, art = row
            console.print(f"{pad}[cyan]E:{ev.id}[/] “{(ev.quote_original or '')[:200]}”")
            console.print(f"{pad}   [dim]{art.final_url or art.url} · captured "
                          f"{art.fetched_at_utc:%Y-%m-%d %H:%M}Z · sha256 "
                          f"{art.sha256[:16]}…[/]")

        def show(kind: str, oid: int, pad: str, level: int) -> None:
            if kind == "finding":
                f = s.get(Finding, oid)
                if f is None:
                    console.print(f"{pad}[red]F:{oid} missing[/]")
                    return
                console.print(f"{pad}[bold]F:{f.id}[/] {f.kind}/{f.epistemic_status} "
                              f"({f.confidence:.2f}) {f.text}")
            elif kind == "relation":
                r = s.get(Relation, oid)
                console.print(f"{pad}[bold]relation R{oid}[/] {r.type} "
                              f"{r.src_entity_id}->{r.dst_entity_id}" if r else f"{pad}R{oid}?")
            elif kind == "event":
                e = s.get(EventRow, oid)
                console.print(f"{pad}[bold]event V{oid}[/] {e.type}: {e.description}"
                              if e else f"{pad}V{oid}?")
            elif kind == "evidence":
                evidence_line(oid, pad)
                return
            if level >= depth:
                return
            for inf in s.scalars(select(Inference).where(Inference.conclusion_type == kind,
                                                         Inference.conclusion_id == oid)):
                console.print(f"{pad}  └ by [italic]{inf.method}[/] ({inf.created_by})")
                for p in s.scalars(select(InferencePremise).where(
                        InferencePremise.inference_id == inf.id)):
                    show(p.premise_type, p.premise_id, pad + "     ", level + 1)
            for ev_id in s.scalars(select(EvidenceLink.id).where(
                    EvidenceLink.target_type == kind, EvidenceLink.target_id == oid)):
                evidence_line(ev_id, pad + "  ")

        show("finding", finding_id, "", 0)


# --------------------------------------------------------------------------- resolution


def _local_llm(a):
    from osint.llm.local import LocalLLM

    return LocalLLM(get_models_config().local, slots=a.settings.concurrency.llm_slots)


def _inv_id_or_none(a, investigation: str | None) -> int | None:
    if investigation is None:
        return None
    with a.session_factory() as s:
        return _find_investigation(s, investigation).id


@app.command()
def embed(investigation: Annotated[str | None, typer.Argument()] = None) -> None:
    """Compute missing embeddings (entities, documents, events) on the local GPU."""
    import asyncio

    from osint.llm.embed import embed_missing

    a = App()
    inv = _inv_id_or_none(a, investigation)

    async def go():
        llm = _local_llm(a)
        try:
            return await embed_missing(a, llm, inv)
        finally:
            await llm.aclose()

    console.print(f"embedded: {asyncio.run(go())}")


@app.command()
def er(
    investigation: Annotated[str | None, typer.Argument(help="Scope (default: all).")] = None,
    no_llm: Annotated[bool, typer.Option(help="No LLM judge: auto-merge or review only.")] = False,
    dry_run: Annotated[bool, typer.Option(help="Show decisions without merging.")] = False,
    show: int = 25,
) -> None:
    """Fuzzy entity resolution: embeddings + transliteration + LLM judge; reversible merges."""
    import asyncio

    from osint.llm.embed import embed_missing
    from osint.resolution.er import EntityResolver

    a = App()
    inv = _inv_id_or_none(a, investigation)

    async def go():
        llm = _local_llm(a)
        try:
            await embed_missing(a, llm, None, kinds=("entity",))
            return await EntityResolver(a, None if no_llm else llm).run(
                inv, use_llm=not no_llm, dry_run=dry_run)
        finally:
            await llm.aclose()

    rep = asyncio.run(go())
    t = Table("score", "A", "B", "via", "decision", "reason")
    for d in sorted(rep.details, key=lambda d: -d["score"])[:show]:
        t.add_row(f"{d['score']:.2f}", d["names"][0][:30], d["names"][1][:30],
                  ",".join(d["via"]), d.get("decision", ""), (d.get("reason") or "")[:60])
    console.print(t)
    console.print(f"candidates {rep.candidates}: auto-merge {rep.would_auto}, "
                  f"LLM-merge {rep.would_llm}, judged different {rep.judged_different}, "
                  f"to review {rep.sent_to_review}, below threshold {rep.below_threshold}"
                  + ("  [yellow](dry run: nothing changed)[/]" if dry_run else ""))


@app.command("er-undo")
def er_undo(merge_id: int) -> None:
    """Undo an entity merge (aliases, mentions, relations and roles move back)."""
    from osint.resolution.merge import MergeError, undo_merge

    try:
        with App().session_factory() as s, s.begin():
            m = undo_merge(s, merge_id)
            console.print(f"undone: entity {m.loser_id} split back out of {m.winner_id}")
    except MergeError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None


@app.command()
def merges(limit: int = 30) -> None:
    """List entity merges (most recent first)."""
    from osint.storage.db import Entity, EntityMerge

    with App().session_factory() as s:
        t = Table("id", "winner", "loser", "method", "score", "reverted", "rationale")
        for m in s.scalars(select(EntityMerge).order_by(EntityMerge.id.desc()).limit(limit)):
            w, lo = s.get(Entity, m.winner_id), s.get(Entity, m.loser_id)
            t.add_row(str(m.id), f"{w.canonical_name} ({w.id})", f"{lo.canonical_name} ({lo.id})",
                      m.method, f"{m.score or 0:.2f}", "yes" if m.reverted_at else "",
                      (m.rationale or "")[:60])
        console.print(t)


# --------------------------------------------------------------------------- linking & graph


def _post_run(a, inv_id: int | None) -> None:
    """After collection: embeddings, corroboration, candidate links, graph projection."""
    import asyncio

    from osint.linking.corroboration import corroborate
    from osint.linking.linker import generate_candidates
    from osint.llm.embed import embed_missing
    from osint.storage.graph import make_driver, sync_graph

    async def emb():
        llm = _local_llm(a)
        try:
            return await embed_missing(a, llm, None)
        finally:
            await llm.aclose()

    try:
        n = asyncio.run(emb())
    except Exception as e:  # noqa: BLE001 - post-processing must not fail the run
        console.print(f"[yellow]embedding skipped[/]: {e}")
        n = {}
    with a.session_factory() as s, s.begin():
        c = corroborate(s, inv_id)
        links = generate_candidates(s, a.ontology)
    try:
        with make_driver(a.settings) as d, a.session_factory() as s:
            g = sync_graph(s, d)
    except Exception as e:  # noqa: BLE001
        g = {"error": str(e)[:100]}
    if a.settings.evidence.seal_after_run:
        try:
            from osint.evidence.seal import seal

            r = seal(a)
            if r is not None:
                g["sealed_manifest"] = r.manifest_id
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]sealing failed[/]: {e}")
    console.print(f"[dim]post-run: embedded {sum(n.values()) if n else 0}, "
                  f"{c.targets} facts corroborated ({c.single_source} single-source), "
                  f"{c.contradictions} new contradiction(s), "
                  f"{links.hard + links.soft} new link candidate(s), graph {g}[/]")


@app.command()
def corroborate(investigation: Annotated[str | None, typer.Argument()] = None) -> None:
    """Count independent sources per fact and detect contradictions."""
    from osint.linking.corroboration import corroborate as run_corroborate

    a = App()
    inv = _inv_id_or_none(a, investigation)
    with a.session_factory() as s, s.begin():
        r = run_corroborate(s, inv)
    console.print(f"{r.documents} documents in {r.origin_clusters} origin clusters; "
                  f"{r.clustered_events} events in {r.incident_clusters} same-incident clusters; "
                  f"{r.targets} facts, {r.single_source} single-source; "
                  f"{r.contradictions} new contradiction(s)")


@app.command()
def link(
    investigation: Annotated[str | None, typer.Argument(
        help="Let Claude decide this investigation's candidates (omit: candidates only).")] = None,
    fresh: bool = False,
) -> None:
    """Find candidate links between investigations; with an investigation, Claude decides."""
    from osint.linking.linker import generate_candidates

    a = App()
    with a.session_factory() as s, s.begin():
        rep = generate_candidates(s, a.ontology)
    console.print(f"new candidates: {rep.hard} hard, {rep.soft} soft "
                  f"({rep.skipped_low} generic overlaps skipped)")
    if investigation is None:
        return
    inv = _inv_id_or_none(a, investigation)
    out = _claude_call(_analyst().link, inv, fresh=fresh)
    if out.result is None:
        console.print("no open candidates for this investigation")
        return
    d = out.result.data or {}
    console.print(f"confirmed {d.get('confirmed', [])}, rejected {d.get('rejected', [])}")
    if d.get("summary"):
        console.print(d["summary"])
    _job_footer(out.result)
    links(investigation)


@app.command()
def links(investigation: str, status: str | None = None) -> None:
    """Show this investigation's links to other investigations."""
    from osint.analyst.tools import AnalystTools

    a = App()
    inv = _inv_id_or_none(a, investigation)
    t = AnalystTools(a.session_factory, a.ontology, a.registry, a.raw_store, inv)
    tab = Table("id", "other", "tier", "score", "status", "via", "explanation")
    for c in t.cross_links(inv, status, limit=200):
        via = c["via"].get("name") or c["via"].get("description") or str(c["via"]["id"])
        tab.add_row(str(c["link_id"]), c["other_investigation"]["name"], c["tier"],
                    f"{c['score']:.2f}", c["status"], f"{c['via']['type']}: {via}"[:40],
                    (c["explanation"] or "")[:70])
    console.print(tab)


@app.command("graph-sync")
def graph_sync() -> None:
    """Rebuild the Neo4j projection from Postgres."""
    from osint.storage.graph import ensure_schema, make_driver, sync_graph

    a = App()
    with make_driver(a.settings) as d, a.session_factory() as s:
        ensure_schema(d)
        console.print(sync_graph(s, d))


@app.command("key-players")
def key_players_cmd(investigation: Annotated[str | None, typer.Argument()] = None,
                    top: int = 15) -> None:
    """Central entities (brokers/hubs) and communities in the network."""
    from osint.linking.network import key_players

    a = App()
    inv = _inv_id_or_none(a, investigation)
    with a.session_factory() as s:
        r = key_players(s, inv, top)
    t = Table("entity", "type", "betweenness", "degree", "community")
    for p in r["players"]:
        t.add_row(f"{p['name']} ({p['entity_id']})", p["type"], f"{p['betweenness']:.3f}",
                  f"{p['degree']:.3f}", str(p["community"]))
    console.print(t)
    for c in r["communities"]:
        console.print(f"  community {c['id']} ({c['size']}): {', '.join(c['members'])}")


# --------------------------------------------------------------------------- refresh / schedule


@app.command("refresh")
def refresh_cmd(
    investigation: str,
    since: Annotated[str | None, typer.Option(help="Search window: day|week|month|year")] = None,
    run_now: Annotated[bool, typer.Option("--run/--no-run")] = True,
) -> None:
    """Re-run searches and feeds for new material (captured pages are not re-fetched)."""
    from osint.orchestrator.refresh import refresh

    a = App()
    inv = _inv_id_or_none(a, investigation)
    n = refresh(a, inv, since)
    console.print(f"re-armed {n} collector task(s)" + (f" (time_range={since})" if since else ""))
    if run_now and n:
        _run(str(inv))


@app.command()
def schedule(
    investigation: str,
    every: Annotated[str, typer.Option(help="Interval: 30m, 6h, 1d")] = "6h",
    since: Annotated[str | None, typer.Option(help="Search window on refresh")] = "week",
    analyze: Annotated[bool, typer.Option(help="Claude analyze when knowledge changed")] = False,
    extract_role: Annotated[str | None, typer.Option(
        help="Extraction model for scheduled runs, e.g. agent_heavy (accurate, overnight)")] = None,
    disable: bool = False,
) -> None:
    """Refresh an investigation on a schedule (executed by `osint daemon`)."""
    from osint.orchestrator.refresh import parse_every, set_schedule

    a = App()
    inv = _inv_id_or_none(a, investigation)
    sch = set_schedule(a, inv, parse_every(every), since, analyze, enabled=not disable,
                       extract_role=extract_role)
    state = "disabled" if disable else f"every {every}, next {sch.next_run_at:%Y-%m-%d %H:%M}Z"
    console.print(f"schedule for investigation {inv}: {state}"
                  + (", with Claude analysis" if analyze else "")
                  + (f", extraction model {extract_role}" if extract_role else ""))


@app.command()
def daemon(
    once: Annotated[bool, typer.Option(help="Process due schedules once and exit "
                                            "(for Windows Task Scheduler).")] = False,
    poll: Annotated[int, typer.Option(help="Seconds between checks.")] = 60,
) -> None:
    """Run due schedules: refresh, collect, post-process, optional Claude analysis."""
    import time

    from osint.analyst.jobs import fingerprint
    from osint.llm.claude_cli import ClaudeJobError
    from osint.orchestrator.refresh import due_schedules, finish_schedule, refresh

    a = App()
    while True:
        for sch in due_schedules(a):
            console.rule(f"schedule {sch.id}: investigation {sch.investigation_id}")
            before = fingerprint(a, sch.investigation_id)
            result: dict = {"rearmed": refresh(a, sch.investigation_id, sch.time_range)}
            try:
                _run(str(sch.investigation_id), extract_role=sch.extract_role)
            except typer.Exit:
                pass
            changed = fingerprint(a, sch.investigation_id) != before
            result["changed"] = changed
            if sch.analyze and changed:
                try:
                    out = _analyst().analyze(sch.investigation_id)
                    result["analyze_job"] = out.result.job_id
                except ClaudeJobError as e:  # quota or failure: collection still happened
                    result["analyze_error"] = str(e)[:300]
            finish_schedule(a, sch.id, result)
            console.print(f"schedule {sch.id} done: {result}")
        from osint.evidence.integrity import due as integrity_due
        from osint.evidence.integrity import run_integrity_check

        if integrity_due(a):
            r = run_integrity_check(a)
            mark = "[green]ok[/]" if r["ok"] else f"[red]{len(r['problems'])} problem(s)[/]"
            console.print(f"daily integrity check: {r['files']} files, "
                          f"{r['custody_entries']} custody entries: {mark}")
        if once:
            return
        time.sleep(poll)


@app.command()
def reextract(
    investigation: str,
    role: Annotated[str, typer.Option(help="Model role from models.yaml.")] = "agent_heavy",
    all_docs: Annotated[bool, typer.Option(
        "--all", help="Also documents judged irrelevant before.")] = False,
    run_now: Annotated[bool, typer.Option("--run/--no-run")] = True,
) -> None:
    """Re-extract an investigation's documents with another (e.g. the accurate) model."""
    from osint.orchestrator.refresh import reextract as do_reextract

    a = App()
    inv = _inv_id_or_none(a, investigation)
    n = do_reextract(a, inv, role, only_relevant=not all_docs)
    console.print(f"queued {n} extraction task(s) with role {role}")
    if run_now and n:
        _run(str(inv))


@app.command("snapshot")
def snapshot_cmd(no_raw: Annotated[bool, typer.Option(help="Skip the raw evidence zip.")] = False) -> None:
    """Back up Postgres (pg_dump), raw evidence, manifests and config, with checksums."""
    from osint.orchestrator.refresh import snapshot

    out = snapshot(App(), include_raw=not no_raw)
    console.print(f"snapshot written: {out}")


# --------------------------------------------------------------------------- generic collect


@app.command()
def collect(
    investigation: str,
    plugin: str,
    params: Annotated[str, typer.Argument(help='JSON, e.g. \'{"channels": ["durov"]}\'')],
    priority: int = 100,
    run_now: Annotated[bool, typer.Option("--run", help="Run the queue right away.")] = False,
) -> None:
    """Queue any collector with JSON params (validated; account-based sources refused)."""
    import json

    from osint.orchestrator.investigations import InvestigationError, queue_collection

    a = App()
    inv = _inv_id_or_none(a, investigation)
    try:
        tid, created = queue_collection(a, inv, plugin, json.loads(params), priority)
    except (InvestigationError, ValueError) as e:
        console.print(f"[red]{e}[/]")
        names = [c.name for c, _ in a.registry.list("collector")]
        console.print(f"collectors: {', '.join(names)}")
        raise typer.Exit(1) from None
    console.print(f"task {tid} {'queued' if created else 'already queued'}")
    if run_now:
        _run(str(inv))


# --------------------------------------------------------------------------- enrichment


@app.command()
def enrich(
    investigation: str,
    enrichers: Annotated[str, typer.Option(help="Comma list (default: all installed).")] = "",
    limit: Annotated[int, typer.Option(help="Max entities per enricher.")] = 200,
    run_now: Annotated[bool, typer.Option("--run/--no-run")] = True,
    again: Annotated[bool, typer.Option(help="Re-run enrichments that already ran.")] = False,
) -> None:
    """Enrich entities: domains (RDAP/DNS), places (OSM), BTC wallets, sanctions screening."""
    from osint.core.models import TaskSpec
    from osint.orchestrator import queue
    from osint.storage.db import Entity, InvestigationRef

    a = App()
    inv = _inv_id_or_none(a, investigation)
    wanted = {e.strip() for e in enrichers.split(",") if e.strip()}
    plugins = [cls for cls, _ in a.registry.list("enricher") if not wanted or cls.name in wanted]
    queued = 0
    with a.session_factory() as s, s.begin():
        ents = s.scalars(select(Entity).where(
            Entity.merged_into_id.is_(None),
            Entity.id.in_(select(InvestigationRef.object_id).where(
                InvestigationRef.investigation_id == inv,
                InvestigationRef.object_type == "entity")))).all()
        for cls in plugins:
            todo = [e for e in ents if any(a.ontology.entity_is_a(e.type, t)
                                           for t in cls.entity_types)][:limit]
            for e in todo:
                tid, created = queue.enqueue(s, TaskSpec(
                    investigation_id=inv, type="enrich", plugin=cls.name,
                    params={"entity_id": e.id}, priority=130))
                if not created and again:
                    from sqlalchemy import update as sa_update

                    from osint.storage.db import Task

                    s.execute(sa_update(Task).where(Task.id == tid, Task.status != "running")
                              .values(status="pending", attempts=0, error=None))
                    created = True
                queued += int(created)
            console.print(f"  {cls.name}: {len(todo)} entities")
    console.print(f"queued {queued} enrichment task(s)")
    if run_now and queued:
        _run(str(inv))


# --------------------------------------------------------------------------- export


@app.command()
def export(
    investigation: str,
    fmt: Annotated[str, typer.Option("--format", help="stix | ftm | gexf (comma list ok)")] = "stix",
) -> None:
    """Export an investigation: STIX 2.1, FollowTheMoney or GEXF (Gephi)."""
    from datetime import datetime

    from osint.plugins.exporters.formats import Scope

    a = App()
    inv = _inv_id_or_none(a, investigation)
    out_dir = a.settings.data_path / "exports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    with a.session_factory() as s:
        scope = Scope(s, inv)
        for name in [f.strip() for f in fmt.split(",") if f.strip()]:
            try:
                exp = a.registry.create("exporter", name)
            except Exception:  # noqa: BLE001
                console.print(f"[red]unknown format {name!r}[/]")
                raise typer.Exit(1) from None
            path = exp.write(scope, out_dir / f"inv{inv}-{stamp}{exp.suffix}")
            console.print(f"[green]\u2713[/] {name}: {path}")


# --------------------------------------------------------------------------- web UI


@app.command()
def ui(port: int = 8765, open_browser: Annotated[bool, typer.Option("--open/--no-open")] = True) -> None:
    """Web GUI on 127.0.0.1: investigations, collection, graph, evidence, Claude jobs, review."""
    import threading
    import webbrowser

    import uvicorn

    from osint.ui.app import create_app

    url = f"http://127.0.0.1:{port}/"
    console.print(f"OSINT Workbench on {url} (local only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run(create_app(), host="127.0.0.1", port=port, log_level="warning")


# --------------------------------------------------------------------------- data hygiene


@app.command("retract")
def retract_cmd(
    relation_id: int,
    reason: Annotated[str, typer.Option(help="Why this relation is wrong.")],
    by: str = "user:cli",
) -> None:
    """Retract a wrong relation (kept for the record, hidden from analysis and exports)."""
    from osint.extraction.retract import retract

    with App().session_factory() as s, s.begin():
        r = retract(s, relation_id, reason, by)
        console.print(f"retracted relation {r.id} ({r.type})")


@app.command("retract-citation")
def retract_citation_cmd(
    evidence_id: int,
    reason: Annotated[str, typer.Option(help="Why this citation is wrong.")],
    by: str = "user:cli",
) -> None:
    """Retract one wrong citation [E:n]; its relation is retracted only if nothing valid is left."""
    from osint.extraction.retract import retract_citation

    with App().session_factory() as s, s.begin():
        console.print(retract_citation(s, evidence_id, reason, by))


@app.command()
def unretract(relation_id: int) -> None:
    """Undo a relation retraction."""
    from osint.extraction.retract import unretract as do_unretract

    with App().session_factory() as s, s.begin():
        r = do_unretract(s, relation_id)
        console.print(f"relation {r.id} ({r.type}) is active again")


@app.command()
def cleanup() -> None:
    """Retract LLM-made relations of enrichment-only types (e.g. designated_by)."""
    from osint.extraction.retract import cleanup_disallowed

    a = App()
    with a.session_factory() as s, s.begin():
        ids = cleanup_disallowed(s, a.ontology)
    console.print(f"retracted {len(ids)} relation(s): {ids}")


# --------------------------------------------------------------------------- evaluation

eval_app = typer.Typer(no_args_is_help=True, help="Quality evaluation and metrics.")
app.add_typer(eval_app, name="eval")


@eval_app.command("extraction")
def eval_extraction(
    role: Annotated[str, typer.Option(help="Model role from models.yaml.")] = "agent",
    model: Annotated[str | None, typer.Option(help="Override the model (any Ollama tag).")] = None,
) -> None:
    """Score a local model against the hand-annotated gold set (P/R/F1, quote accuracy)."""
    import asyncio

    from osint.evals.extraction import run_extraction_eval, save

    a = App()
    run = asyncio.run(run_extraction_eval(a, role, model))
    t = Table("doc", "entities P/R", "relations P/R", "events P/R", "quotes ok", "relevance", "s")
    for d in run.docs:
        t.add_row(d.id, f"{d.entities.p:.2f}/{d.entities.r:.2f}",
                  f"{d.relations.p:.2f}/{d.relations.r:.2f}", f"{d.events.p:.2f}/{d.events.r:.2f}",
                  f"{d.quotes_verified}/{d.quotes_total}", "ok" if d.relevant_ok else "[red]wrong[/]",
                  f"{d.seconds:.0f}" + (" [red]err[/]" if d.errors else ""))
    console.print(t)
    tot = run.totals()
    console.print(f"[bold]{run.model}[/]: entities F1 {tot['entities']['f1']:.2f}, "
                  f"relations F1 {tot['relations']['f1']:.2f}, events F1 {tot['events']['f1']:.2f}, "
                  f"quote verification {tot['quote_verification_rate']:.0%}, "
                  f"relevance {tot['relevance_accuracy']:.0%}, {tot['seconds_per_doc']}s/doc")
    console.print(f"saved: {save(a, run)}")


@eval_app.command("history")
def eval_history() -> None:
    """Compare past extraction evaluations (one row per model run)."""
    from osint.evals.extraction import history

    t = Table("when", "model", "extractor", "ent F1", "rel F1", "evt F1", "quotes", "relevance",
              "s/doc")
    for r in history(App()):
        t.add_row(r["created_at"][:16], r["model"], r["extractor"].split("@")[-1],
                  f"{r['entities']['f1']:.2f}",
                  f"{r['relations']['f1']:.2f}", f"{r['events']['f1']:.2f}",
                  f"{r['quote_verification_rate']:.0%}", f"{r['relevance_accuracy']:.0%}",
                  str(r["seconds_per_doc"]))
    console.print(t)


@eval_app.command("reports")
def eval_reports(investigation: Annotated[str | None, typer.Argument()] = None) -> None:
    """Citation metrics for reports: coverage, precision, unresolved, single-source."""
    from osint.evals.health import report_metrics

    a = App()
    inv = _inv_id_or_none(a, investigation)
    with a.session_factory() as s:
        rows = report_metrics(s, inv)
    t = Table("report", "status", "sentences", "coverage", "precision", "unresolved", "single-src")
    for r in rows:
        t.add_row(f"R:{r['report']}" + (f" (fixes R:{r['supersedes']})" if r["supersedes"] else ""),
                  r["status"], str(r["sentences"]), f"{r['citation_coverage']:.0%}",
                  f"{r['citation_precision']:.0%}", str(r["unresolved_markers"]),
                  str(r["single_source_sentences"]))
    console.print(t)


@eval_app.command("health")
def eval_health(investigation: Annotated[str | None, typer.Argument()] = None) -> None:
    """Extraction health on live data: rejection rates, hallucinated quotes, corroboration."""
    from osint.evals.health import extraction_health

    a = App()
    inv = _inv_id_or_none(a, investigation)
    with a.session_factory() as s:
        h = extraction_health(s, inv)
    console.print(f"citations accepted: {h['citations_accepted']}  rejected: {h['rejected']}")
    console.print(f"rejection rate {h['rejection_rate']:.0%}, hallucinated-quote rate "
                  f"{h['hallucinated_quote_rate']:.0%}, single-source facts "
                  f"{(h['single_source_share'] or 0):.0%}, facts with 2+ independent sources: "
                  f"{h['facts_with_2plus_sources']}")
    console.print(f"open review by kind: {h['open_review']}")


# --------------------------------------------------------------------------- review decisions


@app.command()
def decide(
    review_id: int,
    decision: Annotated[str, typer.Argument(help="accept | reject")],
    note: Annotated[str | None, typer.Option(help="Recorded with the decision.")] = None,
    target: Annotated[int | None, typer.Option(help="Entity id (for merges with several candidates).")] = None,
    by: str = "human:cli",
) -> None:
    """Decide a review item (merge, confirm a sanctions listing, acknowledge, dismiss)."""
    from osint.review.actions import decide as do_decide

    a = App()
    try:
        with a.session_factory() as s, s.begin():
            console.print(do_decide(s, a, review_id, decision, by, note, target))
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None


@app.command("decide-link")
def decide_link_cmd(
    link_id: int,
    decision: Annotated[str, typer.Argument(help="confirm | reject")],
    note: Annotated[str | None, typer.Option(help="Why (recorded).")] = None,
    by: str = "human:cli",
) -> None:
    """Confirm (citing evidence from both investigations) or reject a link candidate."""
    from osint.review.actions import decide_link

    a = App()
    try:
        with a.session_factory() as s:
            console.print(decide_link(s, a, link_id, decision, by, note))
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None


@app.command()
def sources(
    investigation: Annotated[str | None, typer.Argument(help="Only sources used here.")] = None,
    backfill: Annotated[bool, typer.Option(
        "--backfill", help="Assign sources to artifacts captured before source tracking.")] = False,
    limit: int = 50,
) -> None:
    """List sources with their reliability grade (A-F) and artifact counts."""
    from sqlalchemy import func, text

    from osint.core.models import CaptureMeta
    from osint.evidence import custody
    from osint.evidence.sources import RELIABILITY, ensure_source
    from osint.storage.db import Artifact, InvestigationRef, Source

    a = App()
    if backfill:
        n = 0
        with a.session_factory() as s, s.begin():
            rows = s.execute(select(Artifact.id, Artifact.capture_meta)
                             .where(Artifact.source_id.is_(None))).all()
            s.execute(text("SET LOCAL osint.maintenance = 'on'"))
            for aid, meta in rows:
                sid = ensure_source(s, CaptureMeta.model_validate(meta))
                if sid is not None:
                    s.execute(Artifact.__table__.update().where(Artifact.id == aid)
                              .values(source_id=sid))
                    n += 1
            s.execute(text("SET LOCAL osint.maintenance = 'off'"))
            if n:
                custody.append(s, "sources_backfilled", "cli:sources", None, {"artifacts": n})
        console.print(f"assigned sources to {n} artifact(s)")
    with a.session_factory() as s:
        q = (select(Source, func.count(Artifact.id)).join(Artifact, Artifact.source_id == Source.id)
             .group_by(Source.id).order_by(func.count(Artifact.id).desc()).limit(limit))
        if investigation:
            inv = _find_investigation(s, investigation)
            q = q.join(InvestigationRef, (InvestigationRef.object_type == "artifact")
                       & (InvestigationRef.object_id == Artifact.id)
                       & (InvestigationRef.investigation_id == inv.id))
        t = Table("id", "grade", "kind", "source", "artifacts", "note")
        for src, n in s.execute(q):
            note = src.reliability_note if src.reliability_note != RELIABILITY[src.reliability] else ""
            t.add_row(str(src.id), src.reliability, src.kind, src.locator, str(n), note or "")
    console.print(t)


@app.command()
def grade(
    source: Annotated[str, typer.Argument(help="Source id or locator (e.g. reuters.com, t.me/x)")],
    reliability: Annotated[str, typer.Argument(help="A-F (Admiralty source reliability)")],
    note: Annotated[str | None, typer.Option(help="Why (shown with the grade).")] = None,
) -> None:
    """Grade a source's reliability: A completely reliable ... E unreliable, F cannot be judged."""
    from osint.evidence.sources import RELIABILITY
    from osint.storage.db import Source

    reliability = reliability.upper()
    if reliability not in RELIABILITY:
        console.print("[red]use A, B, C, D, E or F[/]")
        raise typer.Exit(1)
    with App().session_factory() as s, s.begin():
        src = (s.get(Source, int(source)) if source.isdigit() else
               s.scalar(select(Source).where(Source.locator == source.lower())))
        if src is None:
            console.print(f"[red]no source {source!r}[/] (see `osint sources`)")
            raise typer.Exit(1)
        src.reliability = reliability
        src.reliability_note = note or RELIABILITY[reliability]
        console.print(f"{src.kind} {src.locator}: {reliability} ({src.reliability_note})")


@app.command()
def archive(
    investigation: str,
    undo: Annotated[bool, typer.Option("--undo", help="Restore an archived investigation.")] = False,
) -> None:
    """Archive an investigation (hidden, schedule stopped; evidence and knowledge are kept)."""
    from osint.orchestrator.investigations import set_archived

    a = App()
    inv = _inv_id_or_none(a, investigation)
    console.print(f"investigation {inv}: {set_archived(a, inv, not undo)}")


# --------------------------------------------------------------------------- Tor / profiles

tor_app = typer.Typer(no_args_is_help=True, help="Local Tor client for anonymous investigations.")
app.add_typer(tor_app, name="tor")


def _tor_line(st) -> str:
    if not st.running:
        return f"[red]not running[/] {st.detail}"
    tor_ok = "[green]traffic exits via Tor[/]" if st.is_tor else f"[red]NOT via Tor[/] {st.detail}"
    return f"running, bootstrapped {st.bootstrapped}%, {tor_ok}, exit IP {st.exit_ip}"


@tor_app.command("start")
def tor_start() -> None:
    """Start Tor (background) and verify with check.torproject.org."""
    from osint.net import tor

    console.print("starting Tor (first start can take a minute)...")
    console.print(_tor_line(tor.start(App().settings)))


@tor_app.command("stop")
def tor_stop() -> None:
    """Stop the background Tor process."""
    from osint.net import tor

    console.print("stopped" if tor.stop(App().settings) else "Tor was not running")


@tor_app.command("status")
def tor_status() -> None:
    """Is Tor running, and does traffic really exit through Tor?"""
    from osint.net import tor

    console.print(_tor_line(tor.status(App().settings)))


@app.command()
def network(
    investigation: str,
    profile: Annotated[str | None, typer.Argument(help="standard | anonymous")] = None,
) -> None:
    """Show or set an investigation's network profile (anonymous = Tor only)."""
    from osint.net.profile import PROFILES, profile_of
    from osint.storage.db import Investigation

    with App().session_factory() as s, s.begin():
        inv = _find_investigation(s, investigation)
        if profile is None:
            console.print(f"{inv.name}: {profile_of(inv)}")
            return
        if profile not in PROFILES:
            console.print(f"[red]use one of {PROFILES}[/]")
            raise typer.Exit(1)
        row = s.get(Investigation, inv.id)
        row.config = {**(row.config or {}), "network_profile": profile}
        console.print(f"{inv.name}: network profile set to [bold]{profile}[/]")


if __name__ == "__main__":
    app()
