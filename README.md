# osint-agents

An OSINT workbench for investigating threats, groups and networks from open sources:

- **Local AI models on your GPU** search the web, capture pages, read documents in many
  languages, and pull out who did what, when and where.
- **Claude** (through Claude Code, on your Max subscription) analyses what was found,
  writes findings and threat assessments, and produces reports.
- **Everything is kept** in one knowledge base, so you can pause an investigation and
  continue days later. A new investigation automatically shows its connections to
  earlier ones.
- **Every statement can be proven.** Each claim cites a verbatim quote, and each quote
  points to a preserved, hash-verified, timestamped copy of the source.

You use it through a **web GUI** (recommended) or the **`osint` command line**. Both do
the same things.

> Developers: architecture and code notes are in [CLAUDE.md](CLAUDE.md).

---

## Contents

1. [Setup](#1-setup)
2. [Starting the system](#2-starting-the-system)
3. [Your first investigation](#3-your-first-investigation)
4. [Collecting: where data comes from](#4-collecting-where-data-comes-from)
5. [Network and anonymity](#5-network-and-anonymity)
6. [Reading the results](#6-reading-the-results)
7. [Analysis and reports with Claude](#7-analysis-and-reports-with-claude)
8. [The review queue](#8-the-review-queue)
9. [Evidence: proof, sharing and safety](#9-evidence-proof-sharing-and-safety)
10. [Keeping investigations up to date](#10-keeping-investigations-up-to-date)
11. [Maintenance and limits](#11-maintenance-and-limits)
12. [Command reference](#12-command-reference)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Setup

You need:
- Windows 11
- Docker Desktop
- [Ollama](https://ollama.com)
- [uv](https://docs.astral.sh/uv/)
- the Claude Code CLI, logged in to your subscription
- an NVIDIA GPU with 16 GB of memory

```powershell
# 1. Services: database, graph database, search engine
copy .env.example .env               # then change the passwords in .env
docker compose up -d

# 2. Local AI models
ollama pull huihui_ai/qwen3-abliterated:14b    # main worker
ollama pull qwen3.6:27b                        # accurate mode + reading images (OCR)
ollama pull bge-m3                             # similarity search

# 3. The program and its database
uv sync --extra dev --extra media
uv run python -m osint init
uv run python -m osint doctor        # checks that everything above works
```

> On this machine, Windows Application Control blocks the small `.exe` launchers.
> Always start commands with `uv run python -m osint ...`, never `osint.exe`.

Optional:
- **VPN for blocked sites:** Cloudflare WARP, see [section 5](#5-network-and-anonymity).
- **Tor for anonymous investigations:** see [section 5](#5-network-and-anonymity).

## 2. Starting the system

```powershell
docker compose up -d                 # if the services aren't running
uv run python -m osint ui            # opens http://127.0.0.1:8765
```

The GUI only accepts connections from your own computer. Close the terminal to stop it.
Jobs it started keep running and show up as "lost" after a restart. Their results are
saved anyway.

**GUI map:**

| Page | What it's for |
|---|---|
| **Dashboard** | All investigations with their progress, failures and open review items. "New investigation". |
| **Investigation** | One tab each: Overview, Collect, Graph, Entities, Timeline, Evidence, Findings, Connections, Ask Claude, Reports & export, Review |
| **Search** | Find a person, group, place or identifier across all investigations |
| **Review** | Everything waiting for a human decision |
| **Sources** | Grade how reliable each source is (A–F) |
| **Jobs** | Long-running operations with a live log; cancel/pause |
| **System** | Health checks, Tor on/off, evidence verification, backups, plugin list |

## 3. Your first investigation

### In the GUI

1. On the **Dashboard**, click **New investigation**.
2. Give it a short name and a **focus**: one or two sentences on what you want to know,
   e.g. *"Houthi attacks on Red Sea shipping since 2025: actors, targets, claims"*.
3. Choose how to start:
   - **Let Claude plan it.** Claude writes the key questions and queues searches in
     several languages.
   - **Or** enter search queries, URLs and RSS feeds yourself.
4. Tick **Anonymous (Tor)** if the target must not see your IP (see
   [section 5](#5-network-and-anonymity)).
5. Tick **Run now** and create it.

The run collects pages, reads them and extracts entities. Follow it on the **Jobs** page
or the investigation's **Overview** tab. A first run with ~10 results per query takes
from a few minutes to an hour, depending on how many pages are found.

Then:
- **Graph** and **Entities**: who and what was found.
- **Analyze** (on the Overview or Findings tab): Claude's analysis.
- **Report** (on the Overview tab): a cited report. It appears under Reports & export.

### On the command line

Let Claude plan and run it:

```powershell
uv run python -m osint new redsea --focus "Houthi attacks on Red Sea shipping since 2025: actors, targets, claims" --plan --run
```

Or choose the queries yourself:

```powershell
uv run python -m osint new redsea --focus "Houthi attacks on shipping" `
    -q "Houthi attack ship Red Sea" -q "Houthi claim tanker" --max-results 10 --run
```

Then look at the results and analyse:

```powershell
uv run python -m osint status redsea             # progress and counts
uv run python -m osint entity "Houthi"           # what is known, with quotes
uv run python -m osint analyze redsea            # Claude's findings
uv run python -m osint report redsea             # cited report (Markdown + HTML)
```

**Pausing:** press Ctrl+C at any time, or click **Cancel** on the Jobs page. Unfinished
work goes back in the queue. To continue, run `osint resume redsea` or click **Run**
again. **Retry failed** also re-queues tasks that failed.

## 4. Collecting: where data comes from

Every source here is public and needs **no account or ID**. Sources that would need your
account (the Telegram API, Reddit API, ACLED, …) are refused, and Claude can't request
them either.

**In the GUI:** the **Collect** tab shows a form for each source.
**On the command line:** run `osint collect <inv> <source> '<json>'`, then `osint run <inv>`.

| Source | What it collects | Example parameters |
|---|---|---|
| `searxng` | Web search (many engines) | `{"queries": ["..."], "language": "ar", "time_range": "month"}` |
| `web` | Specific pages | `{"urls": ["https://..."]}` |
| `rss` | News feeds | `{"feeds": ["https://.../rss"]}` |
| `telegram_public` | Public Telegram channels via the `t.me/s` preview, including photos (read with OCR) | `{"channels": ["name"], "max_posts": 200, "since": "2026-01-01", "photos": 4}` |
| `paste` | Paste sites: Pastebin, Rentry, JustPaste.it, ControlC, paste.ee | `{"urls": ["https://pastebin.com/xxxx"], "queries": ["..."]}` |
| `wayback` | Old copies from the Internet Archive | `{"urls": ["example.org/page"], "mode": "spread", "max_snapshots": 5}` |
| `gdelt` | Global news monitoring | `{"queries": ["houthi sourcelang:arabic"], "timespan": "1w"}` |
| `youtube` | Video details and captions; transcribed when there are no captions | `{"urls": ["https://www.youtube.com/@channel"], "max_videos": 20}` |

**Your own files:** use **Collect → Upload**, or `osint evidence add <file>` on the
command line. Uploaded files are stored as evidence like everything else. Images and
scanned PDFs are read with OCR, and their EXIF metadata (camera, time, GPS) is extracted.

**Enrichment** adds facts from reference services. In the GUI it's on the **Overview**
tab; on the command line it's `osint enrich <inv>`.

| Enricher | What it adds |
|---|---|
| `rdap` | Domain and IP registration, DNS |
| `geocode` | Coordinates for places (OpenStreetMap) |
| `btc` | Bitcoin wallet activity |
| `sanctions` | Checks against the UN, US (OFAC), EU and UK sanctions lists |

A sanctions match is recorded as a fact only when it's unambiguous: an organization with
a specific name that matches the list entry's main name. Everything else goes to the
review queue for your decision:

- people
- one-word names
- names shared by several listed groups
- matches on a single alias

**Better extraction:** the default model is fast. For important material, re-read it
with the larger, more accurate model:
- **GUI:** Overview → Re-extract.
- **Command line:** `osint reextract <inv> --role agent_heavy`.

## 5. Network and anonymity

Each investigation uses one of two network profiles. To change it, use the network
switch on the **Overview** tab, or run `osint network <inv> standard|anonymous`.

### Standard: direct first, VPN when blocked

Every page is fetched over your normal connection. If the site blocks it (403/429/
captcha), the fetch is retried through the VPN. If that fails too, a real browser tries
through the VPN. The evidence records which route was used.

The VPN is **Cloudflare WARP** in proxy mode: it's free, needs no account, and only the
fallback traffic goes through it. One-time setup:

```powershell
winget install --id Cloudflare.Warp
$w = "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"
& $w --accept-tos registration new
& $w --accept-tos mode proxy          # BEFORE connecting, so it never takes over your whole PC
& $w --accept-tos proxy port 40000
& $w --accept-tos connect
```

WARP hides your IP from websites, but it isn't anonymity: Cloudflare knows it's you, and
you exit in your own country.

### Anonymous: Tor only

Use this for hostile sources where your identity matters:

```powershell
uv run python -m osint tor start                 # or System → Tor → Start in the GUI
docker compose up -d searxng-tor                 # search engine whose queries also go via Tor
uv run python -m osint new x -q "..." --anonymous --run
```

- **Everything** goes through Tor: page fetches, screenshots, video downloads,
  enrichment and search queries.
- **Fails safe:** if Tor isn't working, the investigation refuses to run rather than
  connecting directly.
- **Each investigation gets its own Tor circuits,** so sites can't link your
  investigations to each other.
- **Expect fewer results:** many sites and some search engines block Tor.
- **Tor hides where you are, not what you do.** Never log in or reuse identifiers.

> Screenshots taken over a direct connection can reveal your location, since sites show
> local weather or a city name. Use the VPN or Tor, or redact screenshots before
> sharing.

## 6. Reading the results

### Entities, relations, events

The local model extracts:
- **entities:** people, groups, places, vessels, wallets, domains, …
- **relations:** e.g. *member of*, *funded by*, *attacked*
- **events:** e.g. an attack, a statement, a meeting

Each one comes with the verbatim quote it was based on. A quote that can't be found word
for word in the source is rejected, so the model can't invent evidence.

Non-English quotes keep the original text and get an English translation next to it.

### Claims vs facts

"Officials **denied** the Brigade had any link to X" doesn't create a link. Denied and
speculative statements ("may", "suspected") are kept as **claims**: cited evidence that
someone said something, not facts in the graph. Reported statements ("police said") are
kept as facts, labelled *reported*.

### Admiralty codes: how much to trust a citation

Every citation shows a two-character code such as **B1**.

- **The letter is the source's reliability, set by you.** Grade sources on the
  **Sources** page or with `osint grade reuters.com B --note "..."`. Ungraded sources
  show **F** ("cannot be judged").

  | Grade | Meaning |
  |---|---|
  | A | completely reliable |
  | B | usually reliable |
  | C | fairly reliable |
  | D | not usually reliable |
  | E | unreliable |
  | F | cannot be judged |

- **The digit is the information's credibility, computed automatically:**

  | Digit | Meaning |
  |---|---|
  | 1 | confirmed by two or more independent sources |
  | 4 | contradicted by another source |
  | 6 | cannot be judged yet |

"Independent" counts origins, not copies: twenty sites reposting one Telegram post count
as one source.

### Machine-read warnings

Quotes taken from OCR (images, scanned PDFs) or from speech transcription are marked
**machine-read**. A model can misread, so check the quote against the image or audio
before relying on it.

### Graph, timeline, connections

- **Graph:** the network, colour-coded by type. Click a node to open the entity. Zoom in
  to see labels. "Mentions" (weak co-occurrence) links are hidden by default.
- **Timeline:** events in order, with their sources.
- **Connections:** links to other investigations (a shared person, wallet, domain, or a
  similar event) and the key players and brokers in the network. Claude, or you on the
  Review page, confirms each link with proof.

## 7. Analysis and reports with Claude

All of these are buttons in the GUI (Overview, Findings, Ask Claude, Reports) and
commands on the command line:

| Action | What Claude does |
|---|---|
| **Plan** (`osint plan`) | Writes key questions and queues searches in several languages |
| **Analyze** (`osint analyze`) | Records findings (facts, patterns, assessments, gaps), each with proof |
| **Threat assessment** (`osint assess`) | Capability, intent, opportunity, likelihood and impact, indicators and warnings |
| **Red team** (`osint red-team`) | Challenges the findings: alternative explanations, weak spots. Run it before a final report. |
| **Ask** (`osint ask <inv> "..."`) | Answers a question from the knowledge base, with citations |
| **Link** (`osint link <inv>`) | Confirms or rejects connections to other investigations |
| **Report** (`osint report`) | Writes a report where every factual sentence is cited |

**Findings.** Each finding is labelled with one of these:

| Label | Meaning |
|---|---|
| observed | seen directly in the evidence |
| reported | a source says so |
| inferred | derived from other facts |
| assessed | an analytic judgement, in estimative language ("likely", …) |

The **Findings** tab, or `osint explain <id>`, shows a finding's proof tree all the way
down to the quotes and screenshots. You can revise or withdraw a finding; its history is
kept. When Claude wants to *raise* confidence or withdraw a finding, that waits for your
approval in Review.

**The report citation check.** Before a report is released, it's checked automatically:
- every citation points to intact evidence
- every factual sentence is cited
- each cited quote really supports its sentence

A failing report is repaired automatically where possible. Otherwise the problem
sentences are listed (`osint report-verify <id>`), and you can release it anyway with a
recorded reason (`osint report-override`).

**Claude usage.** Claude only ever sees short quotes and structured records, never whole
pages. Repeating a request on unchanged data reuses the cached answer. If your usage
limit is reached, the job says so, and collection keeps working locally.

**Export:** STIX 2.1 (threat intel), FollowTheMoney (Aleph) or GEXF (Gephi), from the
Reports & export tab or with `osint export <inv> --format stix,ftm,gexf`.

## 8. The review queue

The **Review** page (or `osint review` / `osint decide`) collects what needs a human:

| Item | Your decision |
|---|---|
| Possible duplicate entities | merge, or keep separate (merges can be undone) |
| Sanctions matches | confirm the listing, or reject |
| Contradictions | acknowledge |
| Image metadata (GPS, camera) | acknowledge; this is a lead, and it can identify people |
| Finding revisions proposed by Claude | accept or reject |
| Rejected extractions (quote not found, weak citation, unknown type) | dismiss only: they can never become facts |

Dismiss-only items can be cleared in bulk.

**Quality checks:**

| Command | What it shows |
|---|---|
| `osint eval health <inv>` | How often extractions are rejected. Many "quote not found" rejections mean the model is struggling; try accurate mode. |
| `osint eval reports` | Citation coverage and precision of reports |
| `osint eval extraction --model <tag>` | Scores a local model on the built-in multilingual test set (`evals/extraction/gold.jsonl`; add your own examples) |

## 9. Evidence: proof, sharing and safety

**What is kept for every capture:**

- the original bytes
- a WARC web archive record with the full server response
- a full-page screenshot, PDF and rendered page (when screenshots are on)
- SHA-256 and SHA-512 hashes
- the route used (direct, VPN, Tor)
- a hash-chained **custody log** of everything done to it

**Integrity.**

- The evidence is **sealed** after every run: signed and independently timestamped
  (RFC 3161 and Bitcoin via OpenTimestamps). This proves it existed at that time and
  hasn't changed since.
- To check everything, run `osint evidence verify` or click **System → Verify evidence**. The
  daemon also checks it daily.
- Evidence can't be edited. Mistakes are corrected by retracting a relation or citation
  (`osint retract`, `osint retract-citation`); the original stays on record.

**Sharing with someone else.**

- `osint evidence bundle <inv> [--report N]` (or **Reports & export → Bundle**) builds a
  zip containing:
  - the report
  - only the cited evidence
  - all the proofs
  - a standalone `verify.py`
- The recipient unzips it and runs `python verify.py`. They need nothing from this
  system.
- Add `--redact-faces` to blur faces in screenshots. Look at the result before sharing:
  detection isn't perfect.

**Contamination (CSAM, malware).** Extremist sources can carry illegal or harmful files.

- **Blocklists:** put hash lists in `data/blocklists/*.txt`, one md5, sha1 or sha256 per
  line. Matching content is refused before it is saved. Only exact copies match: a
  re-encoded image won't.
- **Purge:** `osint evidence purge <artifact-id> --reason "..."` (or the Evidence tab)
  permanently deletes a file and everything derived from it, and blocklists it. The
  custody log records that it happened, never the content.
- **If you encounter CSAM,** report it to your national hotline (an INHOPE member, e.g.
  NCMEC or IWF) as the law requires. Don't keep copies.

## 10. Keeping investigations up to date

| Task | GUI | Command line |
|---|---|---|
| Collect new material once | Overview → Refresh sources | `osint refresh <inv> --since week` |
| Refresh on a schedule (optionally also analyse, or use the accurate model) | Overview → Schedule | `osint schedule <inv> --every 6h [--analyze] [--extract-role agent_heavy]` |
| Run due schedules | System page | `osint daemon --once`, or `osint daemon` to keep running |
| Hide a finished investigation | Archive (nothing is deleted, its schedule stops) | `osint archive <inv>`, `--undo` to restore |

To refresh every hour without a terminal open:

```powershell
schtasks /Create /SC HOURLY /TN "osint-daemon" /TR "cmd /c cd /d C:\code\osint-agents && uv run python -m osint daemon --once"
```

## 11. Maintenance and limits

- **Health:** `osint doctor` (or the System page) checks:
  - the databases and the search engine
  - the AI models and the Claude CLI
  - the GPU
  - VPN, Tor and the blocklists
- **Backup:** `osint snapshot` (or the System page) saves the database, the evidence, the
  proofs and the config, with checksums.
- **Memory (32 GB machine):**
  - Only one AI model is loaded at a time. Text extraction uses the 14B model. Reading
    photos and scanned PDFs (OCR) uses the 27B model, which runs as a batch after the
    text is done. Expect OCR'd photos to appear in the results near the end of a run.
  - Work pauses when free RAM runs low (`concurrency.min_free_ram_gb`, 4 GB).
  - The AI runner is restarted automatically when its memory grows too much
    (`concurrency.recycle_llm_below_gb`).
  - The large model unloads a minute after use.
- **Settings:**

  | File | What's in it |
  |---|---|
  | `config/settings.yaml` | network, concurrency, evidence, media, Tor |
  | `config/models.yaml` | which local model does what; which Claude model each job uses |
  | `config/ontology.yaml` | entity, relation and event types |
  | `.env` | passwords |

- **Media options:**
  - `media.ocr: false` turns off reading text in images.
  - Speech transcription runs on the GPU when available. Otherwise it uses the CPU,
    at about half real time.
- **Your own sources and enrichers:** drop a Python file in `plugins_local/` (see
  [plugins_local/README.md](plugins_local/README.md)). It appears in the GUI with a form
  automatically.

## 12. Command reference

Prefix every command with `uv run python -m`. For example,
`uv run python -m osint status`.

**Investigations and collection**

| Command | What it does |
|---|---|
| `osint new <name> --focus ... [-q/-u/-f ...] [--plan] [--run] [--anonymous]` | Create an investigation |
| `osint run <inv> [--extract-role agent_heavy] [--no-screenshots]` | Collect, read and extract |
| `osint resume <inv> [--retry-failed]` | Continue after a pause or crash |
| `osint status [<inv>]` | List investigations, or show one's progress |
| `osint collect <inv> <source> '<json>'` | Queue a source (see [section 4](#4-collecting-where-data-comes-from)) |
| `osint enrich <inv> [--enrichers rdap,geocode,btc,sanctions]` | Add facts from reference services |
| `osint reextract <inv> --role agent_heavy` | Re-read documents with the accurate model |
| `osint refresh <inv> [--since week]` / `osint schedule <inv> --every 6h` / `osint daemon [--once]` | Keep up to date |
| `osint archive <inv> [--undo]` | Hide, or restore |
| `osint network <inv> standard\|anonymous` / `osint tor start\|stop\|status` | Network profile and Tor |

**Exploring**

| Command | What it does |
|---|---|
| `osint entity <name>` | Everything known about an entity, across investigations |
| `osint findings <inv>` / `osint explain <finding>` | Findings, and a finding's proof tree |
| `osint links <inv>` / `osint key-players [<inv>]` | Cross-investigation links, and key players |
| `osint sources [<inv>]` / `osint grade <source> A-F --note ...` | Sources and their reliability |

**Claude**

| Command | What it does |
|---|---|
| `osint plan` / `analyze` / `assess` / `red-team` / `report <inv>` | See [section 7](#7-analysis-and-reports-with-claude). `analyze` and `assess` take `--fresh` to ignore the cache. |
| `osint ask <inv> "<question>"` | Question and answer, with citations |
| `osint link <inv>` | Claude confirms or rejects link candidates |
| `osint revise <finding> --confidence 0.3 --reason ...` / `--withdraw` | Revise a finding |
| `osint apply-red-team <job>` | Apply a red-team job's suggested confidences |
| `osint report-verify <id>` / `osint report-override <id> --reason ...` | Report citation check, and override |

**Review and corrections**

| Command | What it does |
|---|---|
| `osint review [<inv>] [--recheck]` | Show rejected extractions and candidates |
| `osint decide <review-id> accept\|reject [--note]` | Decide a review item |
| `osint decide-link <link-id> confirm\|reject` | Decide a cross-investigation link |
| `osint er [<inv>]` / `osint merges` / `osint er-undo <id>` | Entity matching, and undoing merges |
| `osint corroborate [<inv>]` | Recount independent sources and contradictions |
| `osint retract <relation> --reason` / `osint unretract` / `osint retract-citation <E> --reason` | Retract wrong facts or citations |
| `osint cleanup` | Retract relations of types only enrichers may create |

**Evidence and export**

| Command | What it does |
|---|---|
| `osint evidence add <file>` | Add your own file as evidence |
| `osint evidence verify` / `osint evidence seal` | Check, or seal, all evidence |
| `osint evidence bundle <inv> [--report N] [--redact-faces]` | Shareable, verifiable zip |
| `osint evidence purge <artifact> --reason ...` / `osint evidence blocklist` | Contamination handling |
| `osint export <inv> --format stix,ftm,gexf` | Export the data |

**System**

| Command | What it does |
|---|---|
| `osint ui [--port 8765] [--no-open]` | Web GUI |
| `osint init` / `osint doctor` | Set up the database / check health |
| `osint snapshot` | Backup |
| `osint graph-sync` | Rebuild the graph database from the main database |
| `osint plugins` / `osint ontology` | List sources and enrichers, and entity types |
| `osint eval extraction\|history\|health\|reports` | Quality metrics |

Every command has `--help`.

## 13. Troubleshooting

| Problem | What to do |
|---|---|
| `osint.exe` blocked, or "Access denied" | Use `uv run python -m osint ...` |
| `pytest` or media features disappeared | `uv sync --extra dev --extra media` (a plain `uv sync` removes them) |
| A check fails in `osint doctor` | Start Docker (`docker compose up -d`) and Ollama, and pull the missing model |
| Anonymous run refuses to start | `osint tor start`, then `docker compose up -d searxng-tor` |
| Many pages "blocked" | Check WARP is connected (`warp-cli status`). Some sites block every automated client; this is recorded, not bypassed. |
| Claude job says the usage limit was hit | Wait for the limit to reset. Local collection keeps working. |
| Run is slow or paused | Low RAM: close other programs (games, launchers, many browser tabs). See the Jobs log. |
| A run started by Claude Code stopped by itself | Claude Code stops its background processes when memory is critically low. Start long runs and `osint ui` from your own terminal. |
| GUI job shows "lost" | The GUI was restarted while it ran. Check `osint status <inv>`, and `osint resume` if needed. |
| Review queue is huge | On the Review page, bulk-dismiss "quote not found" and "ontology" items. They can never become facts anyway. |
