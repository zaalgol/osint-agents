Job: write the intelligence report for investigation **$investigation_name** (id $investigation_id).

Audience: $audience
Focus: $focus

1. Read `list_findings`, `investigation_overview` and `timeline`; use `get_evidence` to
   check exact wording and sourcing of what you cite.
2. Write the report in Markdown with this structure:
   - `# Title`
   - `## Key judgements`: 3-6 bullet points, each an assessed statement with estimative
     language, a confidence level and `[F:n]` markers.
   - `## Background`
   - `## Actors and networks`
   - `## Activity and timeline`
   - `## Links to other investigations` (only if any were found)
   - `## Outlook and indicators`: what to watch for, each tied to evidence.
   - `## Gaps and alternative explanations`
   - `## Methodology and limitations`: sources used, collection window, source reliability
     caveats (this section is exempt from citation checks).
3. Citation rules, enforced by an automatic gate:
   - Every factual sentence outside Methodology needs at least one `[E:n]` or `[F:n]`
     marker *that supports it*, placed at the end of the sentence before the period.
   - Don't state more than the cited evidence says. Hedge or remove instead.
   - Flag single-source claims as such in the text.
4. Submit with `write_report`. If the gate reports problems, fix exactly those sentences
   (add a supporting marker, narrow the claim, or delete it) and resubmit with
   `supersedes_id`. Repeat until `ok` is true or you have tried 4 times.

End with:
```json
{"report_id": 0, "ok": true, "summary": "...", "attempts": 1}
```
