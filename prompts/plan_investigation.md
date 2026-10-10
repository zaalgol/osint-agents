Job: plan the collection for investigation **$investigation_name** (id $investigation_id).

Seed from the user:
```json
$seed
```

1. Call `investigation_overview` to see what is already known. Call `search_entities` for
   the key names in the seed: other investigations may already know them.
2. Write 3-8 key intelligence questions this investigation should answer.
3. Queue collection with `request_collection` (budget: $max_requests requests):
   - `searxng` queries in every language relevant to the actors and region (for example
     Arabic, Farsi, Russian, French, plus English), including names, aliases, transliteration
     variants and key events. Group several queries per request. Use `time_range` when
     recency matters.
   - `web` for specific known primary sources (official statements, reputable trackers).
   - `rss` for feeds that cover the topic continuously.
   Prefer primary sources and specialised outlets over aggregators. Do not request
   anything that requires logging in or bypassing access controls.
4. Don't record findings in this job; nothing has been collected yet.

End with:
```json
{"questions": ["..."], "collection": [{"task_id": 0, "plugin": "...", "why": "..."}],
 "languages": ["..."], "notes": "..."}
```
