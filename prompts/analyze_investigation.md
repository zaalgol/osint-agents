Job: analyse investigation **$investigation_name** (id $investigation_id).

Focus: $focus
Key questions (from the plan, may be empty):
$questions

Existing findings: $finding_count (call `list_findings` and don't duplicate them).

1. Orient yourself: `investigation_overview`, `timeline`, `get_entity` for the most connected
   actors, `shared_entities` for links to other investigations.
2. Record findings with `add_finding`, each resting on evidence:
   - **facts** (observed/reported): who, what, when, where, with their `[E:n]` evidence ids.
   - **patterns** (inferred): recurring targets, methods, timing, geography, networks.
     Give premises (the events/relations/evidence) and the method.
   - **assessments** (assessed): intent, capability, likely next actions, threat level,
     using estimative language and calibrated confidence. Give premises and method.
   - **gaps** (assessed, low confidence): what is unknown and why it matters. A gap still
     needs premises: the evidence showing the gap.
   - **cross-investigation links**: when an actor, account, wallet or method also appears in
     another investigation, record that as an inferred finding citing both sides.
3. Where key questions can't be answered from the evidence, queue targeted collection
   with `request_collection` (budget: $max_requests requests).

Aim for quality over quantity: a few well-supported findings beat many weak ones.

End with:
```json
{"findings": ["[F:n]", "..."], "collection_requested": [0],
 "answered_questions": {"question": "short answer with [F:n]"},
 "open_questions": ["..."]}
```
