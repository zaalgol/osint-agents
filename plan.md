# OSINT Agents: System Plan

## 1. Goals

- **Collection** runs on a local LLM (RTX 5070 Ti, 16 GB VRAM). It handles crawling, scraping, parsing, extraction and triage. It costs nothing per token, so it can run around the clock, and it doesn't refuse the content that OSINT work routinely involves: extremist material, violence, weapons and leaked data.
- **Analysis** runs on Claude Code CLI (Max 5x, $100 plan), in headless mode (`claude -p`). It does the deep reasoning, cross-source aggregation, link analysis and report writing. It only ever reads distilled, structured data, never raw pages, so the subscription quota goes further.
- **Persistent knowledge.** Every run writes to a shared, durable knowledge base. Investigations can be paused and resumed days later. A new investigation (for example, Group B attacks) automatically surfaces links to earlier ones (Group A threats).
- **Extensible.** New sources, extractors, enrichers, analyzers, storage backends and output formats are plugins. Adding one doesn't touch the core.
- **Cited and provable.** Every claim cites its evidence, and every piece of evidence is preserved and can be checked for tampering. Any conclusion can be traced back to the original captured source, and a third party can verify it independently (see section 8).

---

## 2. Local model recommendation

Hardware: RTX 5070 Ti, 16 GB GDDR7, Blackwell (sm_120). Use a runtime built against **CUDA 12.8 or newer**. Current builds of Ollama and llama.cpp support it.

| Role | Model | Quant / VRAM | Why |
|---|---|---|---|
| **Primary agent (default)** | **Qwen3-14B, abliterated / uncensored variant** (for example the `huihui-ai` abliterated builds) | Q5_K_M, about 10.5 GB, which leaves room for a 24–32k context | Strong tool calling and JSON output, multilingual (Arabic, Farsi, Russian and other languages that matter for threat OSINT), fast (~60–80 tok/s). Abliteration removes refusals while keeping capability. |
| **Heavier option** | **Qwen3-30B-A3B-Instruct-2507** (abliterated) | Q4_K_M, about 18 GB. Use llama.cpp `--n-cpu-moe` to keep some experts in system RAM. | MoE with only ~3B active parameters, so it stays fast even when partly offloaded. Better reasoning for harder extraction. Needs at least 32 GB of system RAM. |
| **Alternative** | Mistral-Small-3.2-24B-Instruct | Q4_K_M, about 14 GB | Few refusals even without abliteration, and good at function calling. Leaves less room for context. |
| **Embeddings** | `bge-m3` or `Qwen3-Embedding-0.6B` | about 1–2 GB | Multilingual. Used for dedup, semantic search and entity matching. |
| **Vision / OCR (optional)** | Qwen2.5-VL-7B, or PaddleOCR / Tesseract | loaded on demand | Screenshots, scanned PDFs, images that contain text |

**Runtime:** use **Ollama** to start with (simple, OpenAI-compatible API on Windows). If you need finer control over MoE offload, parallel slots and grammar-constrained JSON, move to **llama.cpp `llama-server`**. The code calls the model through an OpenAI-compatible client only, so switching runtimes (or to vLLM in WSL2) is a config change.

> Re-check the leaderboards (r/LocalLLaMA, the Berkeley Function-Calling Leaderboard) before you commit. The ~14B class improves every few months. Because the model is just config (`models.yaml`), swapping it is cheap.

**Why abliterated matters here:** stock models often refuse to summarize a jihadist manifesto, extract weapon names from a forum post, or process doxxing dumps. The collection layer has to handle that material neutrally. Claude only ever sees structured, analytic summaries.

---

## 3. High-level architecture

```
                        ┌──────────────────────────────────────────┐
                        │            CLI / Web UI (later)          │
                        │  osint new | run | resume | ask | report │
                        └───────────────────┬──────────────────────┘
                                            │
                        ┌───────────────────▼──────────────────────┐
                        │              ORCHESTRATOR                │
                        │  Investigation → Plan → Tasks (DAG)      │
                        │  Persistent task queue + checkpoints     │
                        └──────┬────────────────────────┬──────────┘
                               │                        │
         ┌─────────────────────▼───────┐     ┌──────────▼──────────────────────┐
         │  LOCAL AGENT LAYER (GPU)    │     │  ANALYST LAYER (Claude CLI)     │
         │  Ollama / llama.cpp         │     │  claude -p  + MCP server        │
         │                             │     │                                 │
         │  • Planner-lite / triage    │     │  • Investigation planning       │
         │  • Collector agents         │     │  • Link / pattern analysis      │
         │  • Extractor (NER, events)  │     │  • Cross-investigation linking  │
         │  • Translator               │     │  • Hypothesis generation        │
         │  • Entity resolver (assist) │     │  • Report writing               │
         └──────────────┬──────────────┘     └──────────────┬──────────────────┘
                        │                                   │ (reads/writes via MCP tools)
                        ▼                                   ▼
         ┌──────────────────────────────────────────────────────────────────────┐
         │                     KNOWLEDGE STORE (storage abstraction)            │
         │  Raw evidence store │ Relational (Postgres) │ Graph (Neo4j) │ Vector │
         └──────────────────────────────────────────────────────────────────────┘
```

### Data flow for one investigation

1. **Define.** The user gives a seed: topic, group, people, domains, handles, a time window.
2. **Plan.** Claude (headless) turns the seed into an investigation plan: questions, source list, keywords in several languages, and the collection tasks to run. The plan is saved to the DB.
3. **Collect.** Local agents run the collection tasks: search, crawl, scrape, download. Each artifact is captured as **proof**: raw bytes, a WARC record, a screenshot, hashes, a trusted timestamp, and a custody log entry. Artifacts are stored content-addressed.
4. **Extract.** Local agents turn the raw artifacts into structured records: entities, relations, events, claims, each with confidence and a **verbatim quote plus its offset** in the source. Records whose quote can't be found in the source are rejected. Translation happens here as well.
5. **Resolve.** Entity resolution matches new entities against the global entity registry, across all investigations.
6. **Analyze.** Claude reads the curated graph and records through MCP tools. It finds patterns, assesses threats, generates hypotheses, and can ask for more collection (feedback loop to step 3).
7. **Report.** Claude writes a sourced report (Markdown, HTML or PDF). Every claim carries a citation marker. A **citation verifier gate** checks that every marker resolves to preserved evidence and that the evidence supports the claim. Failing claims are fixed or dropped before the report is released.
8. **Persist and link.** Findings are written back. The cross-investigation linker flags overlaps with other cases.

---

## 4. Tech stack

| Concern | Choice | Notes |
|---|---|---|
| Language | **Python 3.12+** | Best ecosystem for scraping, NLP and data work |
| Project / deps | `uv` | Fast, reproducible |
| Local LLM client | `openai` SDK pointed at Ollama or llama.cpp, plus **Pydantic AI** (or `instructor`) for typed tool calls and structured output | No lock-in to one agent framework |
| Agent orchestration | Own lightweight graph runner on top of the task queue (LangGraph is an option later) | Keeps the system simple and resumable |
| Task queue | **Postgres-backed queue** (`procrastinate`, or a custom `SELECT … FOR UPDATE SKIP LOCKED`) | Durable. Survives restarts, which is what resume needs. No Redis required. |
| HTTP / crawl | `httpx`, **Playwright** (JS sites), **crawl4ai** (LLM-friendly crawling), `trafilatura` (article text) | |
| Search | **SearXNG** (self-hosted metasearch, in Docker), plus APIs where you have keys | |
| Social / platform | Plugin per platform: Telegram (`telethon`), Reddit (`praw`), RSS, YouTube (`yt-dlp` + Whisper for transcripts), archive.org / Wayback | |
| Anonymity (optional) | Per investigation: standard (direct, then WARP VPN, then browser) or anonymous (Tor only, fail closed, per-investigation circuits). **Done** | Some sources need it, most don't |
| Docs / media | `pymupdf`, `exiftool`, Whisper (`faster-whisper`), OCR | |
| NER baseline | `GLiNER` (multilingual, zero-shot, small) plus an LLM for relations and events | GLiNER is fast and cheap. The LLM handles the harder parts. |
| Relational DB | **PostgreSQL 16 + pgvector** | System of record |
| Graph DB | **Neo4j Community** (Docker) | Link analysis and path queries (Cypher). Treated as a *projection* that can be rebuilt from Postgres. |
| Raw store | Filesystem, content-addressed (`data/raw/ab/cd/<sha256>`). MinIO later if needed. | |
| Lite mode | SQLite + `sqlite-vec` + NetworkX | Single file, no Docker. Good for portable or quick runs. |
| Evidence / proof | `warcio` (WARC), Playwright screenshots + PDF, `exiftool`, `hashlib`, `opentimestamps-client`, `rfc3161-client`, `pynacl` (Ed25519 signing) | Proof capture and integrity (section 8) |
| Claude bridge | `claude -p --output-format json` + a custom **MCP server** (`osint-mcp`) exposing DB tools | |
| Infra | Docker Desktop (WSL2 backend) for Postgres, Neo4j and SearXNG. Ollama runs natively on Windows for the GPU. | |

---

## 5. Data model (the core of cross-investigation linking)

Design principle: **entities are global; investigations are scopes.** An entity such as a person, organization, phone number, crypto wallet or Telegram channel exists exactly once, and investigations *reference* it. That's what lets a later investigation of Group B automatically connect to Group A.

### Core tables (Postgres)

```
investigation      (id, name, seed, status, created_at, config_json, parent_id)
task               (id, investigation_id, type, plugin, params_json, status,
                    attempts, depends_on[], checkpoint_json, result_ref, ...)
source             (id, kind, url, platform, reliability_score, first_seen, last_seen)
artifact           (id, sha256, sha512, source_id, fetched_at_utc, mime, lang, path,
                    url, final_url, http_status, capture_meta_json)  -- immutable raw evidence
capture            (id, artifact_id, kind [raw|warc|screenshot_png|pdf_render|
                    media_original|archive_org], path, sha256, created_at)
timestamp_proof    (id, manifest_sha256, method [rfc3161|opentimestamps],
                    proof_blob_path, authority, stamped_at, verified_at)
custody_log        (seq, artifact_id, action, actor [plugin@version|user],
                    at_utc, details_json, prev_hash, entry_hash)  -- hash-chained, append-only
document           (id, artifact_id, text, translated_text, lang, embedding vector)
entity             (id, type, canonical_name, attributes_json, embedding vector,
                    first_seen, last_seen, confidence)
entity_alias       (entity_id, alias, alias_type, lang, source_artifact_id)
mention            (id, entity_id, document_id, span, context, confidence)
relation           (id, src_entity_id, dst_entity_id, type, attributes_json,
                    confidence, valid_from, valid_to)
event              (id, type, time, time_precision, location_entity_id,
                    description, confidence)          -- attacks, threats, meetings...
event_participant  (event_id, entity_id, role)
claim              (id, subject_ref, predicate, object_ref, stance, confidence)
evidence_link      (id, target_type, target_id, artifact_id, document_id,
                    quote_original, quote_translated, char_start, char_end,
                    media_locator [page|hh:mm:ss|bbox], quote_verified bool)
inference          (id, conclusion_type, conclusion_id, method, rationale,
                    confidence, created_by)
inference_premise  (inference_id, premise_type [evidence|claim|relation|finding],
                    premise_id)                       -- proof tree
corroboration      (claim_id, independent_source_count, origin_cluster_ids[],
                    contradicting_claim_ids[])
investigation_ref  (investigation_id, object_type, object_id, relevance, added_by)
finding            (id, investigation_id, kind, text, confidence, created_by
                    [agent/claude/human], epistemic_status
                    [observed|reported|inferred|assessed], evidence_ids[],
                    inference_id)                     -- must have evidence or inference
cross_link         (id, investigation_a, investigation_b, via_object, kind, score,
                    explanation, status [candidate/confirmed/rejected])
run_log            (id, task_id, agent, model, prompt_hash, tokens, duration, error)
```

Key properties:
- **Provenance everywhere.** Every relation, event, claim and finding links back to artifacts via `evidence_link`, or through an `inference` proof tree that ends in evidence. Nothing exists without a source. DB constraints and triggers enforce this.
- **Confidence and the Admiralty code.** Source reliability (A–F) and information credibility (1–6) are stored separately, in line with standard intelligence practice.
- **Bitemporal-lite.** `valid_from` / `valid_to` on relations: when a fact was true, as distinct from when it was collected.
- **Immutable evidence.** Raw artifacts are never modified, only added to. Their hashes give integrity.
- **Ontology is config.** Entity, relation and event types live in `ontology.yaml`, and plugins can extend them. The defaults roughly follow STIX 2.1 and FtM (FollowTheMoney) so data can be exported.

### Graph projection (Neo4j)

A sync job projects `entity`, `relation`, `event` and `investigation_ref` into Neo4j as nodes and edges, with investigation IDs stored as properties. If the projection drifts or gets corrupted, rebuild it from Postgres. Neo4j is used for:
- shortest paths between two entities or groups
- community detection and centrality (GDS plugin, or NetworkX in lite mode)
- "show me everything within 2 hops of X across all investigations"

### Vector search (pgvector)

Embeddings on documents, entities and events. Used for semantic search, near-duplicate detection, and **fuzzy cross-investigation matching**: similar modus operandi, similar rhetoric, the same unnamed actor described in different words.

---

## 6. Resumability ("continue running after time")

- **All state lives in the DB, none in process memory.** The orchestrator is stateless. On `osint resume <investigation>` it reloads pending, failed and in-progress tasks and carries on.
- **Task statuses:** `pending → running → done | failed | blocked`. A `running` task whose heartbeat has expired is reclaimed after a crash.
- **Checkpoints:** long tasks (crawling a large forum, paging through a Telegram channel) save a cursor (`checkpoint_json`: last message ID, last page or URL frontier) after each batch.
- **Idempotency:** artifacts are deduplicated by sha256, entities by resolution, tasks by `(type, params_hash)`.
- **Incremental refresh:** `osint refresh <investigation>` re-runs collectors with `since=last_seen` to pick up new posts or changes. This can be scheduled (Windows Task Scheduler, or a cron-like loop in the orchestrator).
- **Snapshots:** `osint snapshot` backs up with `pg_dump`, a Neo4j dump and a tarball of the raw store.

---

## 7. Cross-investigation linking

Linking happens on three levels:

1. **Hard links (automatic, deterministic).** The same canonical entity, or the same strong identifier (phone, email, wallet, domain, file hash, Telegram ID), shows up in two investigations. These become `cross_link` candidates immediately.
2. **Soft links (local model plus embeddings).** Similar entities (alias variants, transliterations: "Abu X" / "أبو X" / "Abou X"), similar events (same location and time window, similar MO), and overlapping co-occurrence. These are scored candidates.
3. **Analytic links (Claude).** A periodic or on-demand `osint link --all` job: Claude gets the candidate list and graph neighborhoods through MCP. It confirms or rejects each candidate, explains the connection, and writes `cross_link` rows with a rationale and evidence IDs.

Entity resolution pipeline: normalize (transliteration with ICU, phone/email canonicalization) → block (by type and key features) → score (string similarity, embedding similarity, shared attributes) → auto-merge above a high threshold, send the middle band to an LLM judge (local model; Claude for high-stakes cases), keep separate below a low threshold. **Merges are reversible**: an `entity_merge` log records them.

---

## 8. Citations and proofs

Principle: **no claim without a citation, and no citation without preserved, verifiable proof.** The method follows the *Berkeley Protocol on Digital Open Source Investigations* (UN OHCHR and UC Berkeley Human Rights Center), the standard practice guide for OSINT evidence. Following it doesn't guarantee legal admissibility, but it gives you what admissibility requires.

### 8.1 Evidence capture (proof of what was seen, and when)

Each fetched item gets a **capture bundle**:

| Item | How | Proves |
|---|---|---|
| Raw bytes (HTML / JSON / media file, as received) | stored content-addressed | exact content |
| **WARC record** (ISO 28500) | `warcio`, with full HTTP request and response headers | what the server returned |
| **Full-page screenshot + PDF render** | Playwright | what a human would have seen (needed for JS-heavy and social pages) |
| Capture metadata | final URL after redirects, HTTP status, resolved IP, UTC time from an NTP-synced clock, user agent, proxy / exit node, collector plugin and version | context and reproducibility |
| Hashes | SHA-256 + SHA-512 for every file in the bundle | integrity |
| Platform-native IDs | Telegram message/channel IDs, tweet IDs, post permalinks | stable references even after the URL changes |
| **Third-party archive** (optional per source) | Wayback Machine *Save Page Now* or archive.today, URL stored | an independent copy outside your control. *OPSEC: this leaves a public trace, so it's off by default for sensitive sources.* |

Media: keep the original file (never re-encode), extract EXIF / metadata with `exiftool`, and record the platform's post time separately from the capture time.

### 8.2 Integrity and trusted timestamps

- **Hash manifest:** every hour or so (and at the end of each run), build a Merkle tree over all new capture hashes and store the root.
- **Trusted timestamp** of the manifest root:
  - **RFC 3161** timestamp from a public TSA (for example FreeTSA, DigiCert), or
  - **OpenTimestamps** (anchored in Bitcoin, free).
  
  Together these prove the evidence existed at time T and hasn't changed since. Proof files are stored in `timestamp_proof`.
- **Signed manifests:** the manifests are also signed with a local key (Ed25519 or GPG), so you can show the system produced them.
- **Chain of custody:** `custody_log` is append-only and hash-chained (each entry includes the previous entry's hash), so tampering is detectable. It records every action on an artifact: captured, parsed, OCR'd, translated, cited, exported.
- `osint verify-evidence [<inv>|--all]` re-hashes the files, checks the custody chain, and validates the timestamp proofs.

### 8.3 Citation granularity

A citation (`evidence_link`) points at an **exact location**, not just a URL:
- the verbatim quote **in the original language**, plus a translation if there is one (labeled with the translator: model and version)
- character offsets in the extracted text, and page number / `hh:mm:ss` / image bounding box for PDFs, video, audio and images
- a link to the capture bundle (screenshot, WARC, hashes, archive URL)

**Automatic quote check:** every quote a local agent or Claude produces must be found in the source text (after whitespace and Unicode normalization; fuzzy matching only for OCR and transcripts, with a threshold). If it can't be found, the record goes to `needs_review` and is never silently accepted. This blocks hallucinated citations.

### 8.4 Proof chains for conclusions

Each finding carries an **epistemic status** so readers know what kind of statement it is:
- **observed:** directly visible in the evidence (for example, channel X posted Y at T)
- **reported:** a source *says* it (for example, a news article says group A claimed the attack)
- **inferred:** derived from other facts (for example, the same wallet appears in both groups' donation posts, so there's a financial link)
- **assessed:** analytic judgement (for example, likely intent), worded in estimative language (ICD 203 style: "likely", "almost certainly", plus a confidence level)

Inferred and assessed findings store a **proof tree** (`inference` + `inference_premise`): conclusion → premises → … → evidence. Each step records its method (exact identifier match, entity resolution score, LLM judge, Claude analysis, human analyst) and a confidence. `osint explain <finding-id>` prints the full tree down to the screenshots and quotes.

### 8.5 Corroboration and contradiction

- **Independent-source counting:** syndicated and copy-pasted content is grouped (near-duplicate embeddings, shared origin links, the same media hash). Twenty sites reposting one Telegram post count as **one** source. The original is identified and cited first.
- **Contradictions** are stored explicitly (`corroboration.contradicting_claim_ids`) and must appear in reports, not be dropped quietly.
- **Admiralty grading** (source reliability A–F, information credibility 1–6) is shown with each citation.

### 8.6 Citation enforcement in the pipeline

1. **Local extractors:** the output schema *requires* `quote` + `offsets` for each entity, relation and event. The validator runs the quote check from 8.3.
2. **Claude via MCP:** `add_finding` / `add_hypothesis` **reject** calls that don't include `evidence_ids` or `premise_ids`. `get_evidence` returns the quote, Admiralty grade, capture time and archive link, so Claude can cite accurately.
3. **Reports:** Claude writes inline markers such as `[E:1234]` (evidence) and `[F:56]` (finding / proof tree). Then the **`osint verify-report`** gate runs:
   - every marker resolves to an existing record with intact hashes
   - every factual sentence has at least one marker; uncited sentences are flagged
   - **support check:** for each (sentence, cited quote) pair, an entailment check (local model first, Claude for disputed cases) decides supported, partial or unsupported
   - claims that rest on only one non-independent source are flagged
   - the report **can't be finalized** until the gate passes or a human overrides it (the override is logged)
4. **Rendered output:** footnotes with source URL, platform ID, post time, capture time, archive link, SHA-256 and Admiralty grade. An appendix has an evidence table with links to local screenshots, plus a "proof tree" appendix for the key judgements.

### 8.7 Evidence bundle export (third-party verification)

`osint bundle <inv> [--report <id>]` produces a self-contained zip:
- the report (PDF + Markdown)
- **only the cited** captures (WARC, screenshots, originals)
- `manifest.json` with every hash, the Merkle roots, signatures and timestamp proofs
- the custody log for each included artifact
- a standalone `verify.py` (no dependency on this system) that re-checks hashes, signatures, timestamps and custody chains

Redaction: a `--redact` profile blurs or removes the PII of uninvolved private people in screenshots. The redacted file gets its own hash, linked to the original hash, so integrity can still be shown.

---

## 9. Agent design

### Local agents (each is a plugin with a typed I/O contract)

| Agent | Input | Output | Tools |
|---|---|---|---|
| **Query expander** | seed + plan | multilingual keyword and query sets | none (pure LLM) |
| **Search agent** | queries | candidate URLs with snippets, ranked | SearXNG, platform search |
| **Crawler agent** | URL frontier + scope rules | artifacts | Playwright, crawl4ai, httpx |
| **Relevance triage** | document | relevant? score, reason, next links to follow | none |
| **Extractor** | document | entities, relations, events, claims (JSON schema) | GLiNER + LLM |
| **Translator** | non-English text | English text + key-term glossary | LLM |
| **Media agent** | image / video / audio | OCR text, transcript, EXIF, description | Whisper, OCR, VL model |
| **Resolver assist** | candidate entity pairs | same / different / unsure + reason | none |

Rules for the local agents:
- **Always constrained output.** JSON schema or GBNF grammar, validated with Pydantic. On invalid output, retry once with the error message, then send it to a `needs_review` queue.
- **Small, single-purpose prompts.** A 14B model does well on narrow tasks and badly on big open-ended ones. All the cleverness goes to Claude.
- **GPU concurrency:** one model loaded, with 2–4 parallel slots (`OLLAMA_NUM_PARALLEL` or llama.cpp `-np`). The orchestrator caps in-flight LLM tasks to match. Network-bound tasks (crawling) run at much higher concurrency without the GPU.

### Claude analyst layer

The connection runs through **headless Claude Code**, so it uses the Max subscription, not API billing:

```bash
claude -p "<task prompt>" \
  --output-format json \
  --mcp-config ./config/osint-mcp.json \
  --allowedTools "mcp__osint__*" \
  --append-system-prompt-file ./prompts/analyst_system.md \
  --max-turns 30
```

`osint-mcp` is a local MCP server (Python, official `mcp` SDK). It gives Claude **read and write tools over the knowledge base**, not raw dumps:
- `search_entities`, `get_entity(id, depth)`, `neighborhood(entity_ids, hops)`
- `search_documents(query, semantic=true)`, `get_evidence(ids)` (returns the verbatim quote, translation, offsets, Admiralty grade, capture time, archive link and hash; never whole pages)
- `timeline(entity/investigation, window)`, `graph_query(cypher_readonly)`
- `list_cross_link_candidates`, `confirm_cross_link`, `reject_cross_link` (confirming requires evidence or premise IDs)
- `add_finding`, `add_hypothesis` (**must** include `evidence_ids` or `premise_ids` plus an `epistemic_status`, or the call is rejected), `request_collection(task spec)` (puts work on the local agents' queue: the feedback loop)
- `explain(finding_id)`: the proof tree. `corroboration(claim_id)`: independent source count and contradictions.
- `write_report(markdown)`: the report must use `[E:id]` / `[F:id]` markers. It is saved as a draft until `verify-report` passes (section 8.6).

Claude analyst jobs (each is a prompt template in `prompts/`):
- `plan_investigation`: seed → structured plan and collection tasks
- `analyze_investigation`: patterns, actors, capabilities, intent, timeline, gaps
- `threat_assessment`: likelihood and impact, indicators and warnings, with Admiralty-style confidence
- `link_investigations`: cross-case linking (section 7)
- `red_team`: challenge the current findings, list alternative hypotheses (ACH)
- `report`: final report with every claim cited to evidence IDs, an epistemic status on each judgement, and contradictions included
- `citation_audit`: the Claude side of the verify gate. It reviews sentence/quote pairs that the local check marked "partial" or "unsupported", then fixes or removes the claim.

**Managing the Max 5x quota:**
- Claude never sees raw HTML or full pages, only extracted records and short evidence quotes.
- Batch the work: one analysis session per investigation phase, not one per document.
- `--model` per job: Sonnet for routine linking and summaries, Opus for final assessments and reports.
- A token / usage ledger in `run_log`. When the quota is near its limit, the orchestrator queues Claude jobs and keeps the local pipeline running.
- Results are cached by `(job, input_hash)`.

---

## 10. Plugin / extension system

Everything pluggable is registered through Python **entry points** (`pyproject.toml`) or a `plugins/` folder that's auto-discovered. Each plugin type has an abstract base class:

```python
class Collector(Plugin):       # new data source
    name: str
    params_schema: type[BaseModel]
    async def collect(self, params, ctx) -> AsyncIterator[Artifact]: ...
    def checkpoint(self) -> dict: ...

class Extractor(Plugin):       # new extraction type (e.g. crypto wallets, weapons)
    handles: set[str]          # mime/lang/doc types
    async def extract(self, doc, ctx) -> ExtractionResult: ...

class Enricher(Plugin):        # e.g. WHOIS, geocoding, wallet lookups, sanctions lists
    entity_types: set[str]
    async def enrich(self, entity, ctx) -> list[Fact]: ...

class Analyzer(Plugin):        # local or Claude-backed analysis jobs
    async def analyze(self, scope, ctx) -> list[Finding]: ...

class StorageBackend(Plugin):  # postgres / sqlite / neo4j / networkx / ...
class Exporter(Plugin):        # STIX 2.1, FtM, CSV, GEXF (Gephi), Maltego, PDF report, evidence bundle
class CaptureHandler(Plugin):  # per-platform proof capture (screenshot rules, native IDs, media)
class Timestamper(Plugin):     # rfc3161 / opentimestamps / custom TSA
class LLMProvider(Plugin):     # ollama / llama.cpp / vllm / claude-cli
```

- **`ctx`** gives plugins controlled access to storage, the LLM, an HTTP client (with proxy and rate-limit policy), logging and config. Plugins never open DB connections themselves.
- **Ontology extensions:** a plugin can ship `ontology.yaml` fragments with new entity, relation or event types.
- **Playbooks:** YAML recipes that chain plugins for a type of investigation (for example `playbooks/terror_group_profile.yaml`, `playbooks/attack_reconstruction.yaml`, `playbooks/domain_infra.yaml`). A new use case usually means a new playbook, not new code.

```yaml
# playbooks/terror_group_profile.yaml
name: terror_group_profile
inputs: [group_name, aliases?, region?, since?]
steps:
  - analyzer: claude.plan_investigation
  - collector: searxng      { queries: "{{plan.queries}}" }
  - collector: telegram     { channels: "{{plan.channels}}", since: "{{since}}" }
  - collector: rss          { feeds: "{{plan.feeds}}" }
  - extractor: [gliner_ner, llm_relations, llm_events]
  - enricher:  [geocode, sanctions_lists]
  - analyzer:  claude.analyze_investigation
  - analyzer:  claude.link_investigations
  - analyzer:  claude.report
```

---

## 11. Project layout

```
osint-agents/
├── pyproject.toml
├── docker-compose.yml          # postgres+pgvector, neo4j, searxng
├── config/
│   ├── settings.yaml           # paths, concurrency, proxies, rate limits
│   ├── models.yaml             # local model endpoints/roles, claude job→model map
│   ├── ontology.yaml
│   └── osint-mcp.json
├── playbooks/
├── prompts/                    # local agent prompts + Claude analyst prompts
├── src/osint/
│   ├── cli.py                  # Typer CLI
│   ├── core/                   # models (pydantic), ontology, plugin registry, ctx
│   ├── orchestrator/           # planner, task queue, scheduler, checkpoints
│   ├── llm/                    # local client, structured output, claude_cli bridge
│   ├── storage/                # repo interfaces + postgres/sqlite/neo4j/raw adapters
│   ├── resolution/             # normalization, blocking, scoring, merge log
│   ├── linking/                # cross-investigation candidate generation
│   ├── mcp_server/             # osint-mcp tools for Claude
│   └── plugins/
│       ├── collectors/         # searxng, web, rss, telegram, reddit, wayback, youtube
│       ├── extractors/         # gliner, llm_relations, llm_events, iocs, crypto
│       ├── enrichers/
│       ├── analyzers/
│       └── exporters/
├── data/                       # raw store, exports, reports (gitignored)
└── tests/
```

---

## 12. CLI (first interface)

```
osint init                                   # create DBs, run migrations
osint new "Group A threats" --playbook terror_group_profile --param group_name="..."
osint run <inv>          [--until-phase extract]   # run/continue pipeline
osint resume <inv>                           # pick up after stop/crash
osint refresh <inv> --since 7d               # incremental re-collection
osint status <inv>                           # tasks, counts, queue, quota
osint ask <inv> "Who funds X?"               # ad-hoc Claude Q&A over KB
osint link [--all | <invA> <invB>]           # cross-investigation linking
osint report <inv> --format md|html|pdf
osint export <inv> --format stix|ftm|gexf
osint entity <name|id>                       # everything known, all investigations
osint explain <finding-id>                   # proof tree down to quotes/screenshots
osint evidence <evidence-id> [--open]        # show capture bundle, hashes, custody
osint verify-report <report-id>              # citation gate (resolve + support check)
osint verify-evidence [<inv>|--all]          # re-hash, custody chain, timestamp proofs
osint bundle <inv> [--report <id>] [--redact]  # third-party-verifiable evidence package
```

A web UI (FastAPI plus a graph view such as Cytoscape.js or Sigma.js) comes in a later phase.

---

## 13. Implementation phases

**Phase 0: Foundations (week 1)**: done 2026-10-10
- Repo, `uv`, docker-compose (Postgres+pgvector, Neo4j, SearXNG). Ollama with Qwen3-14B abliterated plus `bge-m3`.
- Pydantic core models, ontology loader, plugin registry, settings.
- Postgres schema and migrations (Alembic); raw content-addressed store.
- Evidence tables (`capture`, `custody_log`, `evidence_link`, `inference`) are in the schema from day one. Adding provenance afterwards is painful.

**Phase 1: Vertical slice (weeks 2–3)**: done 2026-10-10
- Task queue with checkpoints and resume.
- Collectors: SearXNG, generic web (trafilatura/Playwright), RSS.
- Proof capture: raw + WARC + screenshot + hashes + hash-chained custody log.
- Extractor: GLiNER + LLM relations/events with schema-constrained output, **required quotes + offsets, and the quote check**.
- Basic entity resolution (exact + normalized).
- `osint new / run / resume / status` working end to end on one investigation.

**Phase 2: Claude analyst (weeks 3–4)**: done 2026-10-10
- `osint-mcp` server with read tools, then write tools.
- `claude -p` bridge: job templates, JSON result parsing, usage ledger, caching.
- `plan_investigation`, `analyze_investigation` and `report` jobs, with evidence citation.
- Feedback loop: `request_collection` → local queue.
- Citation enforcement in the MCP write tools. `verify-report` gate (marker resolution, uncited-sentence detection, entailment support check). Footnoted report rendering.

**Phase 3: Persistence and linking (weeks 5–6)**: done 2026-10-10
- Neo4j projection sync and graph tools.
- Full entity resolution (fuzzy, transliteration, embeddings, LLM judge, reversible merges).
- Cross-investigation linking (hard, soft, Claude-confirmed).
- `refresh`, snapshots and the incremental scheduler.
- Proof trees (`inference`), `osint explain`, corroboration / independent-source clustering, contradiction tracking.
- Merkle manifests, signing, RFC 3161 / OpenTimestamps, `verify-evidence`, `bundle` export with a standalone `verify.py`.

**Phase 4: Breadth (ongoing)**: no-account sources, enrichers, exporters and UI done 2026-10-10. Account-based sources (Telegram API, Reddit API, ACLED) are deferred by user decision. Whisper transcription, image EXIF + vision-model OCR (images, scanned PDFs) and EU/UK sanctions lists are done. Paste sites are done (by URL + SearXNG `site:` search; the sites' APIs need accounts). The SQLite lite backend is dropped: Postgres from day one (decision 1)
- More collectors: Telegram, Reddit, YouTube + Whisper, Wayback, paste sites, news APIs, sanctions and terror-designation lists (UN, OFAC, EU), GDELT / ACLED for event data.
- Enrichers: geocoding, WHOIS/DNS, crypto wallet lookups.
- Exporters: STIX 2.1, FtM, GEXF.
- Web UI with graph exploration.
- SQLite "lite" backend.

**Phase 5: Quality**: done 2026-10-10
- A gold-standard test set (annotated docs) to measure extraction precision and recall per model, for comparing local models.
- Citation evaluations, tracked as metrics per run:
  - **citation precision:** the share of cited quotes that really support the claim
  - **citation coverage:** the share of factual sentences that are cited
  - **hallucinated quote rate:** quotes not found in the source; target 0, enforced
  - **single-source claim rate**
- Regularly re-run `verify-evidence` (scheduled) to catch storage corruption.
- A human review queue for low-confidence merges and links.

---

## 14. Operational, legal and safety notes

- **Collect open sources only.** Respect the law where you are. No unauthorized access, credential use or bypassing of authentication. Some platforms' ToS restrict scraping; record per-source policy in config.
- **OPSEC for the investigator:** route collectors through VPN/Tor per source, randomize user agents and timing, and never interact with targets (read only). Keep investigation data on an encrypted volume (BitLocker).
- **Contamination handling:** extremist media can contain malware, so open downloaded files in isolated parsers only, never execute them, and store media with no auto-preview. CSAM risk exists on some fringe sources: add hash-based blocking (where you can get access to lists) and a hard stop/purge procedure. **Done:** `data/blocklists/*.txt` (md5/sha1/sha256) checked before anything is stored; `osint evidence purge`.
- **Analytic rigor:** keep source reliability separate from information credibility, cite everything, track confidence, and run the `red_team` job before final reports. LLM output is a lead, not a fact. Nothing in a report is "proven" unless its proof tree ends in preserved, hash-verified evidence.
- **Content deletion:** posts disappear (takedowns, deleted channels). That's why capture happens at collection time, not report time. A citation stays valid after the original URL dies, because the capture bundle, timestamp proof and optional archive copy remain.
- **Claude side:** Claude receives analytic, structured summaries for defensive threat research. Keep the analyst system prompt clear about that purpose. Gratuitous raw extremist content isn't needed at that layer, and leaving it out also saves quota.

---

## 15. Open decisions

1. Full stack (Postgres + Neo4j in Docker) from day one, or start in SQLite lite mode and add Postgres later? **Recommendation: Postgres from day one.** The task queue, pgvector and concurrent workers all benefit, and Docker Desktop is easy on Windows.
2. Which platforms matter most first (Telegram is usually the highest-value source for threat OSINT)?
3. Main languages to support, which drives the model and translation choices.
4. Does a web UI matter early, or is the CLI plus generated reports enough to start?

---

## 16. Standards and references used by this plan

- **Berkeley Protocol on Digital Open Source Investigations**, UN OHCHR and UC Berkeley Human Rights Center (2022 edition): collection, preservation, verification and chain-of-custody practice.
- **ISO 28500, WARC file format**: web capture preservation (`warcio` library).
- **RFC 3161, Time-Stamp Protocol (TSP)**: https://www.rfc-editor.org/rfc/rfc3161
- **OpenTimestamps**: https://opentimestamps.org
- **ICD 203, Analytic Standards** (US ODNI): estimative language, confidence levels, sourcing requirements.
- **Admiralty / NATO System** (STANAG 2511 / AJP-2.1): source reliability A–F, information credibility 1–6.
- **Analysis of Competing Hypotheses (ACH)**, R. Heuer, *Psychology of Intelligence Analysis*.
- **STIX 2.1** (OASIS) and **FollowTheMoney** (OCCRP Aleph): exchange data models.
