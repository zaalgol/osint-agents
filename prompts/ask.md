Question about investigation **$investigation_name** (id $investigation_id):

> $question

Answer from the knowledge base only, using the read tools (they search all investigations).
Cite every factual statement with `[E:n]` or `[F:n]` markers returned by the tools. If the
knowledge base can't answer, say so plainly, then say what collection would answer it.
Keep it concise.

End with:
```json
{"answer_complete": true, "markers_used": ["[E:n]"]}
```
