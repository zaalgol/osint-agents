Job: red-team the analysis of investigation **$investigation_name** (id $investigation_id).

Your role is the devil's advocate. Try to break the current findings before a report
relies on them. Existing findings: $finding_count (call `list_findings`).

1. For each key finding, especially assessments and patterns:
   - Check its evidence with `get_evidence`. Is it single-source, from a low-reliability
     outlet, translated, a claim rather than a fact (`claims_not_facts`), or contradicted
     (`contradictions`, `support.contradicted_by_events`)?
   - Ask what else would explain the same evidence.
2. Do an Analysis of Competing Hypotheses for the 1-3 most important judgements:
   list the hypotheses (including the null hypothesis "unrelated/coincidental"), score the
   evidence for and against each, and identify the evidence that would discriminate between
   them.
3. Record what you find with `add_finding`:
   - kind "hypothesis" for each serious alternative explanation (epistemic_status
     "assessed", premises = the evidence/findings it rests on, method = "ACH" or the
     reasoning used)
   - kind "gap" for each weakness that limits a finding (single source, missing primary
     source, unverified translation, contradiction); premises = the affected finding and
     its evidence
   Don't restate existing findings. Only add what changes confidence.
4. Where discriminating evidence could exist, queue collection with `request_collection`
   (budget: $max_requests).

End with:
```json
{"challenged": [{"finding": "[F:n]", "issue": "...", "suggested_confidence": 0.0}],
 "alternative_hypotheses": ["[F:n]"], "gaps": ["[F:n]"], "collection_requested": [0],
 "verdict": "robust | needs work | unreliable"}
```
