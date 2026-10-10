"""Run analyst jobs with headless Claude Code (``claude -p``) on the Max subscription.

Each job:
  * gets its own MCP config: an `osint` server scoped to one investigation and toolset
  * runs with built-in tools DISABLED (--tools ""), only mcp__osint__* allowed, and
    --permission-mode dontAsk, so it can read and write the knowledge base and nothing else
  * is recorded in the claude_job ledger (tokens, turns, duration, cost-equivalent)
  * is cached by (job, input hash): the same prompt over an unchanged knowledge base
    returns the stored result instead of spending quota
  * strips ANTHROPIC_API_KEY from the environment so usage bills to the subscription,
    unless models.yaml claude.use_api_key is true
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from osint.core.config import get_models_config, project_home
from osint.core.context import App
from osint.storage.db import ClaudeJob

QUOTA_PATTERNS = re.compile(r"usage limit|rate[ _-]?limit|quota|too many requests|429", re.IGNORECASE)
JSON_BLOCK = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)


class ClaudeJobError(RuntimeError):
    pass


class QuotaExceeded(ClaudeJobError):
    """The subscription's usage window is exhausted; try again later."""


@dataclass
class ClaudeResult:
    job_id: int
    text: str
    data: dict[str, Any] | None
    cached: bool
    num_turns: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    duration_ms: int | None = None


def final_json(text: str) -> dict[str, Any] | None:
    """The last ```json block in the final message (jobs end with a JSON summary)."""
    blocks = JSON_BLOCK.findall(text or "")
    for block in reversed(blocks):
        try:
            return json.loads(block)
        except ValueError:
            continue
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


class ClaudeRunner:
    def __init__(self, app: App, binary: str | list[str] | None = None, timeout_s: int = 3600):
        self.app = app
        cfg = get_models_config().claude
        self.cfg = cfg
        if isinstance(binary, list):      # e.g. [python, fake_claude.py] in tests
            self.command = binary
        else:
            self.command = [binary or shutil.which(cfg.binary) or cfg.binary]
        self.timeout_s = timeout_s

    def model_for(self, job: str) -> str:
        return self.cfg.jobs.get(job, self.cfg.default_model)

    def _mcp_config(self, job_id: int, job: str, investigation_id: int, toolset: str,
                    max_requests: int) -> str:
        env = {
            "OSINT_HOME": str(project_home()),
            "OSINT_INVESTIGATION_ID": str(investigation_id),
            "OSINT_JOB": job,
            "OSINT_TOOLSET": toolset,
            "OSINT_MAX_REQUESTS": str(max_requests),
            "PYTHONIOENCODING": "utf-8",
        }
        cfg = {"mcpServers": {"osint": {"command": sys.executable,
                                        "args": ["-m", "osint.mcp_server"], "env": env}}}
        path = self.app.settings.data_path / "mcp" / f"job-{job_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return str(path)

    def run(self, job: str, investigation_id: int, prompt: str, system: str, *,
            fingerprint: str = "", toolset: str = "full", max_turns: int = 40,
            max_requests: int = 30, model: str | None = None, fresh: bool = False,
            budget_usd: float | None = None) -> ClaudeResult:
        model = model or self.model_for(job)
        key = chr(0).join([job, model, toolset, system, prompt, fingerprint])
        input_hash = hashlib.sha256(key.encode()).hexdigest()

        S = self.app.session_factory
        if not fresh:
            with S() as s:
                hit = s.scalar(select(ClaudeJob).where(
                    ClaudeJob.job == job, ClaudeJob.input_hash == input_hash,
                    ClaudeJob.status == "done").order_by(ClaudeJob.id.desc()).limit(1))
                if hit is not None:
                    return ClaudeResult(hit.id, hit.result_text or "", hit.result_json, True,
                                        hit.num_turns, hit.input_tokens, hit.output_tokens,
                                        hit.duration_ms)

        with S() as s, s.begin():
            row = ClaudeJob(investigation_id=investigation_id, job=job, model=model,
                            input_hash=input_hash, status="running")
            s.add(row)
            s.flush()
            job_id = row.id

        cmd = [
            *self.command, "-p", "--output-format", "json", "--model", model,
            "--mcp-config", self._mcp_config(job_id, job, investigation_id, toolset,
                                             max_requests),
            "--strict-mcp-config",
            "--tools", "",                          # no built-in tools: no shell, no files
            "--allowedTools", "mcp__osint__*",
            "--permission-mode", "dontAsk",
            "--append-system-prompt", system,
            "--max-turns", str(max_turns),
            "--no-session-persistence",
        ]
        if budget_usd is not None:
            cmd += ["--max-budget-usd", str(budget_usd)]
        env = dict(os.environ)
        if not getattr(self.cfg, "use_api_key", False):
            env.pop("ANTHROPIC_API_KEY", None)      # bill the Max subscription, not the API

        started = datetime.now(UTC)
        try:
            proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=self.timeout_s,
                                  cwd=str(project_home()), env=env, check=False)
        except subprocess.TimeoutExpired as e:
            self._finish(job_id, "error", error=f"timeout after {self.timeout_s}s")
            raise ClaudeJobError(f"{job}: timed out") from e

        try:
            out = json.loads(proc.stdout)
        except ValueError:
            err = (proc.stderr or proc.stdout or "")[-2000:]
            status = "quota" if QUOTA_PATTERNS.search(err) else "error"
            self._finish(job_id, status, error=err)
            if status == "quota":
                raise QuotaExceeded(err.strip()[:300])
            raise ClaudeJobError(f"{job}: claude exited {proc.returncode}: {err[:500]}")

        text = out.get("result") or ""
        usage = out.get("usage") or {}
        meta = {
            "num_turns": out.get("num_turns"),
            "input_tokens": (usage.get("input_tokens") or 0)
            + (usage.get("cache_creation_input_tokens") or 0),
            "output_tokens": usage.get("output_tokens"),
            "cache_read_tokens": usage.get("cache_read_input_tokens"),
            "cost_usd_equiv": out.get("total_cost_usd"),
            "duration_ms": out.get("duration_ms")
            or int((datetime.now(UTC) - started).total_seconds() * 1000),
            "session_id": out.get("session_id"),
        }
        if out.get("is_error") or out.get("subtype", "success") != "success":
            reason = text or out.get("subtype") or "error"
            status = "quota" if QUOTA_PATTERNS.search(str(reason)) else "error"
            self._finish(job_id, status, error=str(reason)[:4000], result_text=text, **meta)
            if status == "quota":
                raise QuotaExceeded(str(reason)[:300])
            raise ClaudeJobError(f"{job}: {reason}"[:600])

        data = final_json(text)
        self._finish(job_id, "done", result_text=text, result_json=data, **meta)
        return ClaudeResult(job_id, text, data, False, meta["num_turns"], meta["input_tokens"],
                            meta["output_tokens"], meta["duration_ms"])

    def _finish(self, job_id: int, status: str, **fields) -> None:
        with self.app.session_factory() as s, s.begin():
            row = s.get(ClaudeJob, job_id)
            row.status = status
            row.finished_at = datetime.now(UTC)
            for k, v in fields.items():
                setattr(row, k, v)
