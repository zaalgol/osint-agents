# osint-agents

An agent-based OSINT system. Local LLM agents (Ollama on the GPU) collect and extract.
Claude Code CLI does the analysis. A persistent knowledge base links investigations to
each other, and every claim is backed by a citation and preserved, verifiable evidence.

See [plan.md](plan.md) for the full design.

## Status

- **Phase 0 (foundations) is done:** config, domain models, ontology, plugin registry,
  the PostgreSQL schema with proof-enforcing triggers, the content-addressed raw store,
  the hash-chained custody log, and Docker services.
- **Phase 1 (vertical slice) is done:** a durable task queue with resume, SearXNG/web/RSS
  collectors with proof capture (raw + WARC + screenshot/PDF/rendered DOM), parsing,
  local-LLM extraction with schema-constrained output and verbatim-quote verification,
  basic entity resolution, and `new / run / resume / status / entity / review`.
- **Phase 2 (Claude analyst) is done:** an `osint` MCP server over the knowledge base,
  headless `claude -p` jobs (plan, analyze, report, citation audit, ask) with a usage
  ledger and result cache, findings that require proof, the `verify-report` citation gate
  (marker resolution, uncited sentences, LLM support check, evidence hash re-check) and
  footnoted Markdown/HTML reports.
- **Phase 3 (persistence and linking) is done:**
  - bge-m3 embeddings
  - fuzzy entity resolution (transliteration, embeddings, local-LLM judge, reversible merges)
  - corroboration (independent-source counting, contradiction detection)
  - cross-investigation links (hard and soft candidates, confirmed with proof by Claude)
  - Neo4j projection with graph tools (paths, key players, read-only Cypher)
  - refresh, schedules and a daemon, plus snapshots
  - evidence sealing (Merkle manifests, Ed25519, RFC 3161 and OpenTimestamps) and
    independently verifiable evidence bundles
- **Phase 4 (breadth) is done, with no-account sources only:**
  - collectors: public Telegram channels (`t.me/s` preview), Wayback Machine, GDELT news,
    YouTube metadata and captions
  - enrichers: RDAP/DNS, OpenStreetMap geocoding, Bitcoin activity, and UN and OFAC
    sanctions screening
  - exporters: STIX 2.1, FollowTheMoney, GEXF
  - a local web UI
  - direct connections with automatic VPN fallback when a site blocks us
  - a guard that refuses account-based sources
- **Phase 5 (quality) is done:**
  - same-incident clustering (several reports of one incident become one corroborated
    incident)
  - an extraction eval harness with a multilingual gold set (`osint eval extraction`)
  - live quality metrics (`osint eval health`, `osint eval reports`)
  - a review workflow in the UI and the CLI (`osint decide`, `osint decide-link`)
  - a daily integrity check in the daemon
- **Since then:**
  - stance-aware extraction: denied and speculative relations become cited *claims*,
    not graph facts
  - English translations stored next to non-English quotes
  - Whisper transcription for videos without captions (`--extra media`)
  - face redaction for shared bundles (`osint evidence bundle --redact-faces`)

## Setup (Windows)

```powershell
# 1. services: postgres+pgvector, neo4j, searxng
copy .env.example .env          # then edit passwords
docker compose up -d

# 2. local models
ollama pull huihui_ai/qwen3-abliterated:14b
ollama pull bge-m3

# 3. python env + DB schema
uv sync --extra dev
uv run python -m osint init               # migrations, Neo4j constraints, data dirs
uv run python -m osint doctor             # check every dependency
```

> **Windows Application Control note:** on this machine, policy blocks the `.exe`
> launchers that uv generates (`osint.exe`, `alembic.exe`). Always use
> `uv run python -m osint ...` and `uv run python -m alembic ...`.

## Quick start

Let Claude plan, collect, analyse and report:

```powershell
uv run python -m osint new "redsea" --focus "Houthi attacks on Red Sea shipping since 2025: actors, targets, claims" --plan --run
uv run python -m osint analyze redsea          # findings with proof ([F:n])
uv run python -m osint run redsea              # collect what the analyst asked for
uv run python -m osint assess redsea           # threat assessment (capability/intent/indicators)
uv run python -m osint red-team redsea         # challenge the findings before reporting
uv run python -m osint report redsea           # report, citation gate, MD + HTML
uv run python -m osint ask redsea "Which vessels were hit in 2026?"
uv run python -m osint explain 12              # proof tree of finding F:12
```

Or drive collection yourself:

```powershell
uv run python -m osint new "redsea" --focus "Houthi attacks on shipping" `
    -q "Houthi attack ship Red Sea" -q "Houthi claim tanker" --max-results 10 --run
uv run python -m osint status redsea
uv run python -m osint entity "Houthi"          # what we know, with cited quotes
uv run python -m osint review redsea            # what was rejected and why
# Ctrl+C at any time, then:
uv run python -m osint resume redsea
```

## CLI

| Command | What it does |
|---|---|
| `osint new <name> -q/-u/-f ...` | Create an investigation from queries, URLs and feeds |
| `osint run <inv>` | Process the queue: collect, then parse, then extract |
| `osint resume <inv>` | Continue after Ctrl+C or a crash (`--retry-failed` re-queues failures) |
| `osint status [<inv>]` | List investigations, or show one's tasks and knowledge counts |
| `osint entity <name>` | Show an entity across investigations with relations, events and citations |
| `osint review [<inv>] [--recheck]` | Show rejected extractions and resolution candidates; `--recheck` re-verifies rejected quotes |
| `osint plan <inv>` | Claude writes key questions and queues multilingual collection |
| `osint analyze <inv>` | Claude records findings (facts, patterns, assessments, gaps) with proof |
| `osint report <inv>` | Claude writes the report; the citation gate checks it (auto-audit on failure); renders MD + HTML |
| `osint assess <inv>` | Claude threat assessment: capability, intent, opportunity, likelihood/impact, indicators & warnings |
| `osint red-team <inv>` | Claude challenges the findings (ACH, alternative hypotheses, gaps); run it before a final report |
| `osint revise <F> --confidence 0.3 --reason ...` / `--withdraw` | Revise or withdraw a finding (history kept). Claude's downgrades apply; its upgrades and withdrawals wait in Review |
| `osint apply-red-team <job>` | Turn a red-team job's suggested confidences into revisions |
| `osint report-verify <id>` | Re-run the citation gate and list every problem sentence |
| `osint report-override <id> --reason` | Release a report that failed the gate (recorded on the report) |
| `osint ask <inv> "<question>"` | Read-only Q&A over the knowledge base, with citations |
| `osint findings <inv>` / `osint explain <id>` | List findings / show a finding's proof tree down to the quotes |

| `osint er [<inv>] [--dry-run]` / `osint merges` / `osint er-undo <id>` | Fuzzy entity resolution; list or undo merges |
| `osint corroborate [<inv>]` | Independent-source counts per fact; contradiction detection |
| `osint link [<inv>]` / `osint links <inv>` | Cross-investigation link candidates; with `<inv>`, Claude confirms or rejects them with proof |
| `osint graph-sync` / `osint key-players [<inv>]` | Rebuild the Neo4j projection; network brokers and communities |
| `osint refresh <inv> [--since week]` | Re-run searches and feeds for new material |
| `osint schedule <inv> --every 6h [--analyze]` / `osint daemon [--once]` | Recurring refresh (+ optional Claude analysis) |
| `osint reextract <inv> [--role agent_heavy]` | Re-run extraction on existing documents with the accurate model (merges into the knowledge) |
| `osint run <inv> --extract-role agent_heavy` | One run with the accurate extraction model |
| `osint schedule <inv> --every 1d --extract-role agent_heavy` | Nightly refresh with the accurate model (fast model stays the interactive default) |
| `osint snapshot` | pg_dump + raw evidence + manifests + config, with checksums |
| `osint evidence seal` | Merkle manifest + Ed25519 signature + RFC 3161/OpenTimestamps (runs after every `run`) |
| `osint evidence bundle <inv> [--report N]` | Export a zip with the cited evidence, proofs and a standalone `verify.py` |

| `osint collect <inv> <plugin> '<json>'` | Queue any collector, e.g. `telegram_public '{"channels": ["somechannel"]}'` |
| `osint enrich <inv> [--enrichers rdap,geocode,btc,sanctions]` | Enrich entities with outside sources (proof captured, quotes verified) |
| `osint export <inv> --format stix,ftm,gexf` | STIX 2.1 / FollowTheMoney / Gephi |
| `osint ui` | Local web UI on http://127.0.0.1:8765 (read-only) |
| `osint retract <rel> --reason` / `osint unretract <rel>` | Retract a wrong relation (kept on record, hidden from analysis/exports) |
| `osint retract-citation <E> --reason` | Retract one wrong citation; reports citing it fail the gate |
| `osint cleanup` | Retract LLM-made relations of enrichment-only types |

| `osint eval extraction [--model TAG]` / `osint eval history` | Score a local model on the gold set (P/R/F1, quote accuracy); compare runs |
| `osint eval health [<inv>]` / `osint eval reports` | Live metrics: rejection and hallucinated-quote rates, corroboration, report citation coverage and precision |
| `osint decide <review-id> accept\|reject [--note]` | Decide a review item (merge, confirm a listing, acknowledge, dismiss) |
| `osint decide-link <link-id> confirm\|reject` | Human decision on a cross-investigation link (cites both sides) |

### Quality loop

1. `osint eval extraction --model <tag>` scores a model on `evals/extraction/gold.jsonl`
   (8 fictional, hand-annotated documents in EN/AR/RU/FR, including traps: an irrelevant
   text, a denial that must not become a relation, a meeting that isn't a relation). Add
   your own documents to the file to grow the set.
2. `osint eval health <inv>` shows how often the gatekeepers fire on real data. A high
   `quote_not_found` rate means the model invents quotes, a high `weak_citation` rate
   means it cites names instead of statements.
3. The **Review** tab in `osint ui` (or `osint decide`) handles what the machines
   couldn't: merges, sanctions confirmations, contradictions, link candidates. Rejected
   extractions can only be dismissed, never voted into facts.
4. `osint daemon` re-verifies all evidence daily (`integrity_alert` on any problem).

### Resource limits (32 GB machine)

Workers stop claiming new tasks when free RAM drops below `concurrency.min_free_ram_gb`
(running tasks finish), and Chromium screenshot pages are capped by
`concurrency.browser_pages`. Ollama unloads the 27B model one minute after its last use
(`keep_alive` per role in `models.yaml`). Ollama's runner process (`llama-server`) keeps
growing in system RAM during long runs (measured: +9 GB in about 30 minutes) even with
the model fully on the GPU. When available RAM drops below
`concurrency.recycle_llm_below_gb`, the runner unloads the models, which frees that memory
at once, and the next request reloads them.

### Claims vs facts

The extractor labels each relation's stance: `asserted`, `reported` ("police said"),
`denied`, or `speculative` ("may", "suspected"). Asserted and reported relations become
graph facts (reported ones keep `stance: reported`). Denied and speculative ones are
stored as cited **claims**: "Officials denied the Brigade had any link to X" is kept
as evidence of a denial, not as a link. Claude sees them separately
(`claims_not_facts` in `get_entity`).

### Media (optional: `uv sync --extra dev --extra media`)

- **Whisper:** a YouTube video without captions gets its audio stored as evidence and
  transcribed (faster-whisper; `media.*` in settings). Audio is decoded by Playwright's
  Chromium, because the usual decoder (PyAV) is blocked by Windows Application Control
  here. It runs on the GPU if NVIDIA's cuBLAS/cuDNN libraries load, otherwise on CPU
  (about 0.5x real time). Transcripts are labelled as machine transcription.
- **Face redaction:** `osint evidence bundle <inv> --redact-faces` blurs faces in
  screenshots (OpenCV YuNet, model hash-pinned), drops PDF/DOM/media captures that can't
  be redacted, and records each redacted file's original hash. Detection isn't perfect:
  look at the bundle before sharing it.
- **OPSEC note:** screenshots taken over a direct connection can show your approximate
  location, because sites localize by IP (e.g. a weather/location widget in a news
  header). Use the VPN route or redact before sharing.

**Sanctions screening policy:** a match becomes a fact (`designated_by`, citing the
verbatim list entry) only for organizations with a specific, unambiguous name. People,
single-word names, and names shared by several listed parties (e.g. "Ansar Allah" is also
a Hizballah alias) become `sanctions_match` review items for an analyst.

### Sources (all public, no account or ID)

| Collector | Params example |
|---|---|
| `searxng` | `{"queries": ["..."], "language": "ar", "time_range": "month"}` |
| `web` | `{"urls": ["https://..."]}` |
| `rss` | `{"feeds": ["https://.../rss"]}` |
| `telegram_public` | `{"channels": ["name", "https://t.me/name"], "max_posts": 200, "since": "2026-01-01"}` |
| `wayback` | `{"urls": ["example.org/page"], "mode": "spread", "max_snapshots": 5}` |
| `gdelt` | `{"queries": ["houthi sourcelang:arabic"], "timespan": "1w"}` |
| `youtube` | `{"urls": ["https://www.youtube.com/@channel"], "max_videos": 20}` |

Collectors that would need your own account (Telegram API, Reddit API, ACLED, ...)
are refused unless `collection.allow_account_sources: true`, and Claude can't request
them either.

### Network: direct first, VPN when blocked

Each page is fetched down this ladder, stopping at the first that works:

1. **Direct HTTP**, your normal connection.
2. **VPN HTTP**, used when the direct route is blocked (HTTP 401/403/429/451/503, a
   captcha/challenge page) or refused. Names are resolved with DNS-over-HTTPS *through
   the VPN* (`network.vpn_doh`), which gets past DNS-level blocks while TLS is still
   verified for the real hostname. A host that blocked direct stays on the VPN for the
   run.
3. **Real browser** (Chromium, through the VPN), for sites that refuse any non-browser
   client. The browser's main-document response becomes the evidence (WARC, screenshot,
   PDF, DOM).

Every capture records its route and the earlier attempts. Some sites (bot managers like
Akamai) also reject headless browsers. They stay recorded as blocked, and the system does
not try to solve captchas or impersonate a person.

**VPN in use: Cloudflare WARP, proxy mode** (free, no account). Only the fallback goes
through it; your normal traffic doesn't. Setup, already done on this machine:

```powershell
winget install --id Cloudflare.Warp
$w = "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
& $w --accept-tos registration new
& $w --accept-tos mode proxy          # BEFORE connecting: never take over the whole machine
& $w --accept-tos proxy port 40000
& $w --accept-tos connect
```

`network.vpn_proxy: socks5://127.0.0.1:40000`. WARP hides your IP from sites but exits
in your own country, and Cloudflare knows it's you, so it isn't anonymity. For
anonymity-critical collection, Tor is the stronger choice.

After every `run`, a post-run step computes embeddings, updates corroboration,
generates link candidates, syncs the graph and seals new custody entries.

**Windows Task Scheduler** (refresh every hour without a terminal open):
```powershell
schtasks /Create /SC HOURLY /TN "osint-daemon" /TR "cmd /c cd /d C:\code\osint-agents && uv run python -m osint daemon --once"
```

**Verifying a bundle** (anyone, anywhere): unzip it, then run `python verify.py`. Optional
tools: `pip install cryptography` (signature), `openssl` (RFC 3161), `ots` (Bitcoin anchor).

Claude jobs run headless on your Max subscription (`ANTHROPIC_API_KEY` is removed
from their environment). Built-in tools are disabled, so the analyst can only use the
`osint` MCP tools. Results are cached per knowledge state, and usage is recorded in the
`claude_job` table. When the usage limit is hit, the command says so and local
collection keeps working.
| `osint init` | Apply DB migrations, create Neo4j constraints and data directories |
| `osint doctor` | Check Postgres, pgvector, Neo4j, SearXNG, Ollama models, the Claude CLI and the GPU |
| `osint plugins` | List discovered plugins |
| `osint ontology` | Show entity, relation and event types |
| `osint evidence add <file>` | Ingest a file as evidence (hashes, capture, custody entry) |
| `osint evidence verify` | Re-hash all stored evidence and verify the custody chain |

## Tests

```powershell
uv run python -m pytest                   # unit tests, plus integration tests if Postgres is running
uv run python -m pytest -m "not integration"
```

Optional GLiNER NER (CPU): `uv sync --extra dev --extra ner`, then set
`extraction.extractors: [llm, gliner]` in `config/settings.yaml`.

## Layout

```
config/            settings.yaml, models.yaml, ontology.yaml, searxng/
migrations/        alembic (schema + integrity triggers)
plugins_local/     drop-in plugins (auto-discovered)
src/osint/
  core/            config, models, ontology, plugins, context
  storage/         ORM schema, sessions, raw content-addressed store
  evidence/        custody chain, ingest
  plugins/         built-in plugins
  cli.py
tests/
```
