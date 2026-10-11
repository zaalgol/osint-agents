# CLAUDE.md: code and architecture memory

This file is for whoever changes the code (you, Claude). The user guide is
[README.md](README.md). Keep this file current when the architecture changes. It
replaces the old phase-by-phase `plan.md`.

## What the system is

An OSINT workbench with a split brain:

- **Local LLMs** (Ollama on an RTX 5070 Ti, 16 GB) do the bulk work: search, scrape,
  parse, extract, translate, OCR, judge entity matches. They cost nothing per token and
  don't refuse extremist material. They're abliterated models for that reason.
- **Claude Code CLI**, run headless (`claude -p`) on the user's Max subscription, does the
  analysis: planning, findings, threat assessment, red-teaming, linking and reports. It
  only sees distilled records and short quotes through an MCP server, never raw pages,
  to save quota and keep raw extremist content out of that layer.
- **One durable knowledge base** (Postgres + pgvector, Neo4j projection, a
  content-addressed raw store). Entities are global and investigations are scopes, so a
  new case automatically connects to earlier ones.
- **Everything is cited and provable:** no claim without a citation, and no citation
  without preserved, hash-verified evidence. The method follows the Berkeley Protocol
  (see References).

## Hard rules (user decisions; don't break them)

1. **No sources that need the user's account or ID.** That rules out the Telegram API,
   Reddit API, ACLED, the Wayback Save Page Now API and anything with a login. The
   collector guard refuses them unless `collection.allow_account_sources: true`, and
   Claude's `request_collection` can't ask for them either.
2. **Connect directly first; use the VPN only when blocked.** Standard ladder: direct,
   then WARP (socks5 127.0.0.1:40000), then a real browser. The anonymous profile is the
   exception: Tor only, fail closed.
3. **Never edit evidence.** Corrections are new rows: retractions, revisions, custody
   entries. The only way to destroy content is `purge`, which goes through the
   maintenance switch and is custody-logged.
4. **Don't let LLM output become a fact without a verified quote.** Extractions whose
   quote isn't in the source are rejected, and rejected items can only be dismissed in
   review, never accepted.
5. **Claude jobs bill the subscription, not the API:** `ANTHROPIC_API_KEY` is stripped
   from their environment.

## Environment and gotchas (Windows 11)

- **Windows Application Control** blocks uv's `.exe` launchers and some DLLs. Always run
  `uv run python -m osint ...`, `uv run python -m pytest` and `uv run python -m alembic`.
  PyAV and OpenCV 4 are blocked. OpenCV 5 and ctranslate2 work. Audio is decoded through
  Playwright's Chromium for that reason.
- **Always `uv sync --extra dev --extra media`.** A plain `uv sync` uninstalls pytest and
  the media stack.
- **Docker compose project `osint`:**
  - postgres (pgvector, pg16) on :5432
  - neo4j 5 on :7474 and :7687
  - searxng on :8888
  - searxng-tor on :8889. Its engine traffic goes through the host's Tor at
    `host.docker.internal:9050`.
- **Ollama roles** (`config/models.yaml`):
  - `agent`: `huihui_ai/qwen3-abliterated:14b`
  - `agent_heavy` and `vision`: `qwen3.6:27b`. It has vision; OCR takes about 25 s a page.
  - `embedding`: `bge-m3`, 1024 dimensions. This must match the DB vector columns.
- **Outside the repo:**
  - Tor Expert Bundle in `%LOCALAPPDATA%/osint-tor/`
  - portable Node 24 LTS in `%LOCALAPPDATA%/osint-node/node-v24.21.0-win-x64`

  Both had their signatures verified.
- **Secrets, all gitignored:**
  - `.env`: DB passwords. Nested settings use `OSINT_SECTION__KEY`.
  - `config/keys/signing_ed25519.pem`: the evidence signing key.
- **Git:** work happens on branch `osint-baseline`.

## Commands for development

```powershell
uv sync --extra dev --extra media
uv run python -m osint init          # migrations + Neo4j constraints + data dirs
uv run python -m osint doctor        # every dependency, incl. VPN/Tor/blocklists
uv run python -m pytest              # all tests; integration tests need Postgres
uv run python -m pytest -m "not integration"
uv run ruff check src tests          # lint; --fix for import order
uv run python -m alembic revision -m "..."   # new migration (then edit it by hand)

# GUI
$env:Path = "$env:LOCALAPPDATA/osint-node/node-v24.21.0-win-x64;$env:Path"
cd web; npm install; npm run dev     # :5173, proxies /api to `osint ui --no-open` on :8765
npm run build                        # tsc + vite build into src/osint/ui/static (commit it)
```

How integration tests (`@pytest.mark.integration`) get a database:

- Each test creates a throwaway database `osint_test_<hex>` and migrates it to head.
  The database is dropped afterwards.
- The test is skipped when Postgres isn't reachable.
- `pg_settings` points `data_dir` at a temp directory and clears all proxies, so tests
  never use the real VPN or Tor.

## Repository map

```
config/          settings.yaml, models.yaml, ontology.yaml, searxng/, searxng-tor/, keys/
migrations/      alembic: schema + integrity triggers (append-only, custody chain, proof)
prompts/         Claude job prompts + analyst_system.md
evals/extraction gold.jsonl: multilingual hand-annotated extraction gold set
plugins_local/   drop-in plugins, auto-discovered
playbooks/       empty: playbook recipes were planned but not built (see Not built)
web/             React GUI source (built output lives in src/osint/ui/static)
data/            gitignored: raw/, warc, reports, exports, bundles, blocklists/, ui-jobs/
src/osint/
  __main__.py    entry; SIGBREAK handler + OSINT_STOP_FILE watcher (GUI cancel)
  cli.py         Typer CLI (~64 commands); _post_run() runs after every `run`
  core/          config (pydantic-settings), models, ontology, plugins registry,
                 context (App, PluginContext), doctor
  orchestrator/  queue (Postgres SKIP LOCKED), runner, investigations, refresh/schedules
  net/           http Fetcher (route ladder), profile (standard/anonymous), tor
  evidence/      capture/persist_item, browser (Playwright), warc, custody, ingest,
                 parse, sources (Admiralty), merkle/seal/timestamp, integrity,
                 bundle + verify_bundle (standalone verify.py), redact, purge
  extraction/    quotes (verbatim verification), writer (records + evidence links), retract
  media/         image (EXIF, OCR via vision role), transcribe (faster-whisper)
  resolution/    normalize (ICU translit), resolver, er (fuzzy + LLM judge), merge (reversible)
  linking/       corroboration (independent origins, contradictions, incident clusters),
                 linker (cross-investigation candidates), network (Neo4j key players)
  llm/           local (Ollama, schema-constrained JSON, images), embed, claude_cli
  analyst/       jobs (Claude job templates, cache, ledger), tools (MCP tool impls), revisions
  mcp_server/    the `osint` MCP server Claude talks to
  reports/       verify (citation gate), render (footnoted MD/HTML)
  review/        actions: decide review items (merge, sanctions, contradiction, ...)
  enrichment/    enricher base plumbing
  evals/         extraction scoring, health metrics
  storage/       db (SQLAlchemy ORM), session, graph (Neo4j), raw_store (+ Blocklist)
  plugins/       collectors/, extractors/, enrichers/, exporters/, analyzers/
  ui/            app.py (Starlette JSON API + SPA), jobs.py (background job manager)
tests/           pytest; test_phaseN.py are historical names, not a structure to keep
```

## Pipeline

```
seed (focus, queries, urls, feeds)
  └─ [optional] Claude plan_investigation ─ queues multilingual collect tasks
collect  (collector plugin → items) ─ capture bundle + custody + Source row
  └─ parse  (HTML/PDF/media → document text; OCR/transcripts flagged machine_read)
       └─ extract (local LLM per chunk → entities/relations/events/claims + quotes)
            └─ quote check → writer (evidence_link) or review_item (rejected)
post-run (_post_run in cli.py): embeddings → corroboration → ER → link candidates
          → Neo4j sync → seal new custody entries
Claude jobs (on demand): analyze / assess / red-team / link / ask / report
  └─ report → citation gate → rendered MD + HTML (or override, recorded)
enrich (on demand): rdap, geocode, btc, sanctions → facts with captured proof
```

- **Queue** (`orchestrator/queue.py`):
  - Task types: `collect`, `parse`, `extract`, `enrich`.
  - Tasks deduplicate on `(type, params_hash)` and are claimed with
    `FOR UPDATE SKIP LOCKED`.
  - A heartbeat stores checkpoints. Stale `running` tasks are reclaimed.
  - All state is in the DB, so `resume` works after Ctrl+C or a crash.
- **Runner** (`orchestrator/runner.py`):
  - Network tasks (collect, parse, enrich) and LLM tasks (extract) run in separate pools.
  - LLM concurrency matches `OLLAMA_NUM_PARALLEL`.
  - Workers stop claiming when free RAM < `concurrency.min_free_ram_gb`.
  - The Ollama runner is recycled when RAM < `concurrency.recycle_llm_below_gb`, because
    `llama-server` leaks system RAM on long runs.
  - Ctrl+C means a graceful pause: in-flight tasks are released back to the queue
    (exit code 130).
- **Fetch budget:** `max_fetches` per investigation caps collect tasks.

## Data model and invariants

Tables (`storage/db.py`): investigation, task, run_log, source, artifact, capture,
custody_log, manifest, timestamp_proof, document, entity, entity_alias, entity_merge,
mention, relation, event, event_participant, claim, evidence_link, inference,
inference_premise, corroboration, finding, finding_revision, investigation_ref,
cross_link, report, review_item, claude_job, support_stats, schedule, citation_retraction.

**Enforced in the DB** (migration `a1b2c3d4e5f6_integrity_triggers`):

- **Append-only:** `artifact`, `capture`, `custody_log`, `evidence_link` and
  `inference_premise` reject UPDATE, DELETE and TRUNCATE. Only a transaction that runs
  `SET LOCAL osint.maintenance = 'on'` may change them; `purge` and two CLI maintenance
  paths do.
- **Custody chain:** every custody entry stores `prev_hash` and its own `entry_hash`.
  The trigger computes the chain head, so tampering is detectable.
- **Proof required:** `relation`, `event`, `claim` and `finding` need an evidence_link or
  an inference. This is a deferred constraint trigger, so insert the proof in the same
  transaction. `cross_link` needs proof when its status becomes confirmed.
- **Evidence targets** and inference premises must exist (polymorphic checks).

**Design rules in code:**

- **Entities are global.** `investigation_ref` scopes them to investigations.
  - Merges are logged in `entity_merge` and are reversible (`er-undo`).
- **Claims vs facts.** The extractor labels each relation's stance:
  - `asserted` and `reported` become relations.
  - `denied` and `speculative` become cited `claim` rows, never graph edges.
- **Findings** carry an `epistemic_status`: observed, reported, inferred or assessed.
  - Inferred and assessed findings need an `inference` proof tree.
  - Revisions are kept in `finding_revision`. Claude's downgrades apply at once; its
    upgrades and withdrawals become review items.
- **Admiralty** (`evidence/sources.py`). `persist_item` assigns a Source row
  automatically. The source key is:
  - the host for websites (Wayback copies map to the original host)
  - the channel for Telegram and YouTube
  - the site for paste sites
  - the service for enrichers

  Reliability A–F is set by a human. Unknown sources default to F; enrichers default to
  A (sanctions), B (RDAP, btc) or C (geocode). Credibility is computed: 1 with ≥2
  independent origins, 4 if contradicted, otherwise 6. 2, 3 and 5 are human-only.
- **Neo4j is a projection** and can always be rebuilt from Postgres (`graph-sync`).

## Evidence capture

`evidence/capture.py: persist_item` is the single door for collected content:

- **Capture bundle:**
  - raw bytes, content-addressed at `data/raw/ab/cd/<sha256>`
  - SHA-256 and SHA-512
  - a WARC record with full HTTP headers
  - optional Playwright screenshot, PDF and rendered DOM
  - `CaptureMeta`: final URL, status, route, proxy, earlier attempts, collector@version
- **Blocklist first.** `RawStore` checks `data/blocklists/*.txt` (md5/sha1/sha256) before
  any write and raises `BlockedContent`. Only the URL, hash and list name are logged
  (`blocked` custody action). Exact-hash matching only.
- **Seal:** a Merkle manifest over new custody entries, signed with Ed25519 and
  timestamped with RFC 3161 (FreeTSA) and OpenTimestamps. It runs after every `run` and
  daily in the daemon.
- **Bundle:**
  - contents: only the cited captures, `manifest.json`, the custody slices, and a
    standalone `verify.py` with no dependency on this code
  - `--redact-faces` uses OpenCV YuNet with a hash-pinned model; the original hash is
    recorded next to the redacted file
- **Purge** (`evidence/purge.py`):
  - What it removes: the files, the document text, translations, embeddings and quote
    text.
  - The hashes go into `blocklists/purged.txt`. A custody entry records the hashes and
    the reason, never content.
  - Record ids survive.
  - Integrity checks and bundles skip purged items, and reports citing them fail the
    gate.
- **Wayback Save Page Now isn't built:** anonymous use returns 429, and the API needs an
  account (rule 1). The local WARC and timestamps carry the proof.

## Network (`net/`)

**Standard profile.** `Fetcher` tries routes in order: direct, then VPN, then browser.

- Blocked means:
  - HTTP 401, 403, 429, 451 or 503
  - a challenge or captcha page (`block_reason`)
  - a refused connection
- The VPN route resolves DNS over HTTPS through the VPN (`network.vpn_doh`), so TLS is
  still checked against the real hostname.
- A host that blocked the direct route stays on the VPN for the rest of the run.
- The browser fallback goes through the VPN. Its main-document response becomes the
  evidence.

**Anonymous profile.** `net/profile.py: apply_profile(settings, profile, inv_id)` sets:

| Setting | Value |
|---|---|
| `proxy` | `tor.socks_url(inv_id)`: per-investigation SOCKS credentials, `IsolateSOCKSAuth` on port 9050 |
| `browser_proxy` | port 9052 with `IsolateDestAddr`, because Chromium can't send SOCKS auth |
| `vpn_proxy` | `None` |
| `vpn_fallback`, `vpn_doh` | `False` |
| SearXNG | `searxng.tor_url` (:8889), checked to be up |

- **Fails closed:** if Tor isn't up (`tor.auto_start` tries to start it), the run
  refuses to start.
- **Loopback exception:** only loopback hosts bypass the proxy. A loopback response that
  redirects off-host is refused.
- **WebRTC** is restricted to proxied UDP.
- **Route labels:** captures through a proxy are labelled `proxy` or `browser+proxy`,
  never `direct`.

**What does the profile apply to?** It applies to everything that leaves the machine for
targets: fetches, Playwright, yt-dlp, enrichers and timestamping. It doesn't apply to
Claude or Ollama.

## Extraction and resolution

- **`plugins/extractors/llm.py`:**
  - Documents are chunked (`chunk_text`), then Ollama returns JSON constrained to a
    schema (Pydantic) built from the ontology.
  - Invalid output is retried once with the error, then goes to review.
- **`extraction/quotes.py`:** every quote must be found in the source after whitespace
  and Unicode normalization. Fuzzy matching is used only for `machine_read` documents.
  A failed quote becomes a `quote_not_found` review item.
- **Weak citations:** quotes that are just a name, not a statement, get `weak_citation`.
- **Translations:** non-English quotes get an English translation stored next to them,
  labelled with the translator model.
- **Ontology:** `config/ontology.yaml`. Plugins can ship fragments. Enrichment-only
  relation types (e.g. `designated_by`) can't be produced by the LLM; `osint cleanup`
  retracts any that slipped through.
- **Resolution** (`resolution/`):
  1. Normalize: ICU transliteration and identifier canonicalization.
  2. Block by type and key features.
  3. Score: string similarity, embeddings, shared attributes.
  4. Auto-merge above the high threshold. The middle band goes to the local LLM judge
     (`agent` role by default), with review for uncertain cases.
- **Corroboration** (`linking/corroboration.py`):
  - Syndicated or copied content collapses to one origin.
  - Contradictions are explicit.
  - Same-incident clustering merges several reports of one event into one incident.
- **Cross-links** (`linking/linker.py`):
  - Hard candidates: a shared entity or strong identifier.
  - Soft candidates: embeddings, aliases, similar events.
  - Claude confirms or rejects each candidate with proof, or the human does
    (`decide-link`).

## Enrichers

| Enricher | What it does |
|---|---|
| `rdap` | RDAP plus DNS for domains and IPs |
| `geocode` | OpenStreetMap Nominatim |
| `btc` | Bitcoin address activity |
| `sanctions` | UN, OFAC, EU and UK lists |

**List URLs** (all public, no token beyond the EU's fixed public one):

| List | URL |
|---|---|
| OFAC | `sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV` |
| EU | `webgate.ec.europa.eu/fsd/fsf/public/files/xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw` |
| UK | the FCDO CSV |

**When a match becomes a fact.** It becomes a `designated_by` fact citing the verbatim
list entry only when all of these hold:

- the entity is an organization
- the name is specific (not a single word)
- the name matches the entry's primary name, or two of its names
- the match isn't ambiguous across parties

Otherwise it becomes a `sanctions_match` review item.

**How parties are clustered** (`_parties`):

- Entries are the same party if they share another key, or if the matched name is the
  primary name on both.
- The same party on several lists counts once.
- Apostrophes are stripped from keys.
- A match on a single alias goes to review.

Accepting a review item records the right authority (`review/actions.py:
LIST_AUTHORITIES`).

## Media

- **`media/image.py`:**
  - EXIF: camera, original time, GPS. GPS or camera details open a `media_metadata`
    review item.
  - OCR through the `vision` role (`LocalLLM.chat_json(images=...)`), for images and for
    PDF pages without a text layer (up to `media.max_ocr_pages`).
  - OCR documents get parser `ocr:...` and `meta.ocr.machine_read = true`.
- **`media/transcribe.py`:** faster-whisper for YouTube videos that have no captions.
  Audio is decoded through Chromium, because PyAV is blocked.
- **Telegram photos** are captured as `telegram:<post>:photoN` and OCRed.

## Claude analyst layer

**How a job runs** (`llm/claude_cli.py: ClaudeRunner`):

```
claude -p --output-format json --model <per job> --mcp-config <osint server>
  --allowedTools "mcp__osint__*" --tools ""
  --append-system-prompt-file prompts/analyst_system.md
```

- Built-in tools are disabled, and `ANTHROPIC_API_KEY` is stripped (rule 5).
- Model and turn limits are set per job in `models.yaml`. Opus is used for analyze,
  assess, red-team and report; Sonnet for the rest.
- `QuotaExceeded` is raised when the usage limit is hit. Local collection keeps working.

**Jobs** (`analyst/jobs.py: Analyst`), one prompt each in `prompts/`:

| Job | Prompt |
|---|---|
| plan | `plan_investigation` |
| analyze | `analyze_investigation` |
| assess | `threat_assessment` |
| red-team | `red_team` |
| link | `link_investigations` |
| report | `report` |
| citation audit | `citation_audit` |
| ask | `ask` |

- Results are cached by a fingerprint of the knowledge state; `--fresh` bypasses it.
- Usage is logged in `claude_job`.

**MCP tools** (`mcp_server/server.py`, implemented in `analyst/tools.py`):

| Group | Tools |
|---|---|
| Read | `investigation_overview`, `search_entities`, `get_entity`, `neighborhood`, `search_documents`, `read_document`, `get_evidence`, `timeline`, `list_findings`, `shared_entities`, `cross_links`, `key_players`, `shortest_path`, `graph_query` (read-only Cypher), `contradictions` |
| Write | `add_finding`, `request_collection`, `propose_finding_revision`, `confirm_cross_link`, `reject_cross_link`, `write_report`, `verify_report` |

- `add_finding` and `confirm_cross_link` reject calls without `evidence_ids` or
  `premise_ids`.
- `get_evidence` returns the quote, translation, Admiralty code, `machine_read` and the
  capture time, never whole pages.
- `request_collection` is the feedback loop into the local queue. It is guarded by
  rule 1.

**Report citation gate** (`reports/verify.py`). Reports use `[E:id]` and `[F:id]`
markers. The gate checks that:

- every marker resolves to a record whose evidence hashes are intact
- every factual sentence is cited (exempt sections and sentences: `is_exempt`)
- the cited quote supports the sentence (a local LLM entailment judge, with Claude's
  `citation_audit` for disputed cases)
- retracted or purged citations fail

A failing report gets an automatic audit. It can be released only with
`report-override`, which records the reason. `reports/render.py` writes footnotes with
the URL, capture time, SHA-256 and the Admiralty code.

## Plugins

- **Base classes** are in `core/plugins.py`:

  | Base class | Key method or attribute |
  |---|---|
  | `Collector` | `collect` + `params_schema` |
  | `Extractor` | `handles` + `extract` |
  | `Enricher` | `entity_types` + `enrich` |
  | `Analyzer` | |
  | `Exporter` | |
  | `StorageBackend` | |
  | `LLMProvider` | |
  | `CaptureHandler` | |
  | `Timestamper` | |

- **Registration:** built-ins are registered through the `osint.plugins` entry points in
  `pyproject.toml`. Drop-in plugins are any `*.py` in `plugins_local/`.
- **Rules:**
  - Plugins only touch the world through `PluginContext` (`ctx.http`, `ctx.browser`,
    `ctx.llm`, `ctx.session()`, `ctx.raw_store`), so network policy, proxies, the
    blocklist and provenance are enforced in one place.
  - Never open your own httpx client or DB connection in a plugin.
  - `params_schema` (Pydantic) is also what the GUI turns into a form, so give fields
    descriptions and defaults.
- **Built-ins:**

  | Kind | Plugins |
  |---|---|
  | collectors | searxng, web, rss, telegram_public (`t.me/s` preview), paste, wayback (CDX read-only), gdelt, youtube (yt-dlp), echo (tests) |
  | extractors | llm, gliner (optional) |
  | enrichers | rdap, geocode, btc, sanctions |
  | exporters | stix, ftm, gexf |

## Web GUI (`web/` + `src/osint/ui/`)

**Frontend** (`web/`):

- Stack: Vite, React 19, TypeScript, react-router, TanStack Query, and cytoscape with
  fcose.
- npm versions are pinned exactly, to releases at least 14 days old. The build output is
  committed to `src/osint/ui/static`.
- Code layout:
  - `src/api.ts`: types and `get`/`post`/`upload`
  - `components/`: `ui.tsx`, `SchemaForm`, `EvidenceList`, `Shell`
  - `pages/`
  - `tabs/`: one per investigation tab
- `ToastProvider` must stay inside `BrowserRouter`, because toasts render `<Link>`.

**Backend** (`ui/app.py`):

- A Starlette JSON API under `/api/...`.
- Every non-API path serves the SPA, with a per-server CSRF token injected into
  `<meta name="csrf">`.
- Writes require that token and a localhost `Origin`.
- It binds to 127.0.0.1, with a strict CSP.
- Captured pages are served inert.

**Jobs** (`ui/jobs.py`). Long actions run as `python -m osint <args>` subprocesses.

- Actions are a whitelist (`build_args`). Arguments are passed as a list, with no shell.
- Logs and the index are in `data/ui-jobs/`.
- One queue-processing job per investigation; Claude jobs don't block.
- **Cancel:**
  1. The GUI writes `<id>.stop`.
  2. `__main__.py` watches `OSINT_STOP_FILE` and raises SIGINT, which pauses the job
     like Ctrl+C.
  3. After 90 s, `taskkill /T /F` kills the process tree. The venv launcher has a child
     process, and Ctrl+Break can't reach processes without a console.
- After a GUI restart, running jobs show as `lost`.

**Adding a GUI action:**

1. Add a case to `build_args` in `ui/jobs.py`.
2. Add a button using `JobButton` or `useStartJob`.
3. If it needs a new read endpoint, add it in `ui/app.py`, then rebuild.

## Config

- `config/settings.yaml`, overridable from `.env` with `OSINT_<SECTION>__<KEY>`.
- **Sections:** `data_dir`, `postgres`, `searxng` (`url`, `tor_url`), `concurrency`,
  `evidence`, `network` (`proxy`, `vpn_proxy`, `vpn_fallback`, `vpn_doh`,
  `browser_proxy`), `media`, `tor`, `collection`, `extraction`, `plugin_dirs`,
  `ontology_files`.
- `config/models.yaml` holds the local roles and the Claude job → model map.

## Conventions

- **Python 3.12, ruff.** Typer for the CLI. SQLAlchemy 2 ORM sessions are scoped per
  unit of work.
- **Comments explain why, not what.** Module docstrings state the design reason.
- **Schema changes** need a new Alembic migration. Never edit an applied one.
- **Write tests for:**
  - new invariants
  - new collectors: mock HTTP, no live network in unit tests
  - new GUI endpoints: `tests/test_gui_api.py` with `FakeProc`
- **After changing anything under `web/`,** run `npm run build` and commit the static
  output.
- **README** is user-facing: features, how to use them, what the results mean. Put
  internals here.

## Not built (and why)

| Item | Why |
|---|---|
| Account-based sources (Telegram API, Reddit API, ACLED, paste-site APIs, Save Page Now API) | rule 1 |
| SQLite "lite" backend | dropped: Postgres from day one |
| Playbooks (YAML plugin chains) | `osint plan` with Claude covers the use case for now; `playbooks/` is a placeholder |
| PDF report rendering | Markdown and HTML only |
| Perceptual-hash (re-encoded) blocklist matching | exact hashes only |

## References (standards the design follows)

- **Berkeley Protocol on Digital Open Source Investigations** (UN OHCHR and UC Berkeley
  HRC, 2022): collection, preservation, verification, chain of custody.
- **ISO 28500 (WARC):** web capture preservation (`warcio`).
- **RFC 3161, Time-Stamp Protocol:** https://www.rfc-editor.org/rfc/rfc3161
- **OpenTimestamps:** https://opentimestamps.org
- **ICD 203, Analytic Standards** (US ODNI): estimative language and confidence.
- **Admiralty / NATO system** (STANAG 2511 / AJP-2.1): reliability A–F, credibility 1–6.
- **Analysis of Competing Hypotheses** (Heuer, *Psychology of Intelligence Analysis*):
  the red-team job.
- **STIX 2.1** (OASIS) and **FollowTheMoney** (OCCRP Aleph): export models.
