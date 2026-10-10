Job: threat assessment for investigation **$investigation_name** (id $investigation_id).

Focus: $focus

Build the assessment from the knowledge base (`list_findings`, `timeline`, `get_entity`,
`key_players`, `contradictions`, `cross_links`). Record each judgement with `add_finding`
(kind "assessment", epistemic_status "assessed", premises = the findings/evidence it rests on,
method = how you reasoned). Use estimative language (almost certainly / likely / roughly even
chance / unlikely / remote) and give a confidence level for each.

Assess, per main actor:
1. **Capability:** demonstrated means, reach, resources (cite events and evidence).
2. **Intent:** stated and demonstrated targets and goals (cite statements and claims;
   separate what they *say* from what they *do*).
3. **Opportunity:** targets, geography, timing, constraints.
4. **Likelihood and impact** of the most likely and the most dangerous course of action in
   the next 3 months.
5. **Indicators and warnings:** concrete observable signs that would raise or lower the
   assessment. Record each as a finding of kind "indicator".
6. **Key uncertainties:** what would change the assessment most (kind "gap").

Rest only on cited evidence. Where the evidence is thin, say so and lower the confidence.

End with:
```json
{"actors": [{"name": "...", "threat_level": "low|moderate|elevated|high|critical",
             "confidence": "low|moderate|high", "findings": ["[F:n]"]}],
 "indicators": ["[F:n]"], "gaps": ["[F:n]"], "summary": "..."}
```
