"""Stand-in for the `claude` CLI in tests: records its invocation and returns canned JSON.

Behaviour is controlled with FAKE_CLAUDE_MODE: ok (default) | quota | error | garbage.
"""

import json
import os
import sys

argv = sys.argv[1:]
prompt = sys.stdin.read()
mode = os.environ.get("FAKE_CLAUDE_MODE", "ok")
record = {
    "argv": argv,
    "prompt_head": prompt[:200],
    "api_key_present": "ANTHROPIC_API_KEY" in os.environ,
}
with open(argv[argv.index("--mcp-config") + 1], encoding="utf-8") as fh:
    record["mcp_config"] = json.load(fh)
log = os.environ.get("FAKE_CLAUDE_LOG")
if log:
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

if mode == "garbage":
    print("Error: something went wrong", file=sys.stderr)
    sys.exit(2)
if mode == "quota":
    print(json.dumps({"type": "result", "subtype": "success", "is_error": True,
                      "result": "Claude AI usage limit reached|1760000000", "num_turns": 1}))
    sys.exit(1)
if mode == "error":
    print(json.dumps({"type": "result", "subtype": "error_max_turns", "is_error": True,
                      "result": "", "num_turns": 40}))
    sys.exit(1)

summary = {"questions": ["Who is behind the attacks?"], "collection": [], "echo": len(prompt)}
print(json.dumps({
    "type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
    "result": "Done.\n```json\n" + json.dumps(summary) + "\n```",
    "usage": {"input_tokens": 10, "cache_creation_input_tokens": 90, "output_tokens": 50,
              "cache_read_input_tokens": 5},
    "total_cost_usd": 0.01, "duration_ms": 1234, "session_id": "s-1",
}))
