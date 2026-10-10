Job: decide which candidate links between investigation **$investigation_name** (id $investigation_id)
and other investigations are real.

There are $candidate_count open candidates. Call `cross_links` with status "candidate".

For each candidate:
1. Look at what connects the two cases: `get_entity` for an entity link (relations and
   events on both sides), `timeline`/`get_evidence` for an event link. `shortest_path` and
   `key_players` (with investigation "all") help to see the wider network.
2. **Confirm** (`confirm_cross_link`) only if there is a substantive connection: the same
   actor, account, wallet, organization, or the same incident/campaign. Give evidence ids
   from BOTH investigations wherever possible, and an explanation saying exactly what
   connects them and how confident you are.
3. **Reject** (`reject_cross_link`) generic overlaps: countries, big cities, well-known
   public figures mentioned in passing, unrelated incidents that merely look alike.
4. Where a confirmed link changes the picture (e.g. one actor active in both cases),
   record an inferred finding with `add_finding`, citing both sides.

End with:
```json
{"confirmed": [0], "rejected": [0], "findings": ["[F:n]"], "summary": "..."}
```
