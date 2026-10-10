Job: repair the citations of report R:$report_id in investigation **$investigation_name**.

The citation gate found these problems:
```json
$issues
```

For each problem sentence:
- `uncited`: find a supporting `[E:n]`/`[F:n]` with the tools, or delete the sentence.
- `unsupported`/`partial`: the cited evidence doesn't (fully) say this. Narrow the claim to
  what the evidence says, cite better evidence, or delete it. `missing` names the gap.
- `unresolved:...`: the marker doesn't exist. Find the right one or remove the claim.
- `single_source`: keep it, but say in the sentence that it rests on a single source.

Don't change sentences that have no problems. Submit the full corrected Markdown with
`write_report` and `supersedes_id=$report_id`, then repeat until `ok` is true (max 3 tries).

Current report Markdown:
````markdown
$markdown
````

End with:
```json
{"report_id": 0, "ok": true, "fixed": 0, "removed": 0}
```
