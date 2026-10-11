"""Background jobs for the web GUI: long operations run as `python -m osint ...` subprocesses.

Why subprocesses: runs, Claude jobs and exports take minutes to hours, use a lot of
memory, and the CLI already handles pause/resume. A crash or cancel can't take the
GUI server down. Each job's output goes to data/ui-jobs/<id>.log; the index survives a
GUI restart.

Only whitelisted actions are accepted, and arguments are passed as a list (no shell).
At most one queue-processing job (run, resume, enrich, refresh, ...) runs per
investigation, because two runners on the same queue would fight over memory.
Cancel creates the job's stop file; the CLI watches it and interrupts itself exactly
like Ctrl+C (graceful pause, tasks released back to the queue). If it hasn't exited
after a grace period, the whole process tree is killed.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path


class JobError(ValueError):
    pass


@dataclass
class Job:
    id: int
    action: str
    label: str
    args: list[str]
    investigation_id: int | None
    queue_worker: bool
    status: str = "running"           # running | done | failed | cancelled | lost
    pid: int | None = None
    exit_code: int | None = None
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    finished_at: str | None = None


def _s(v) -> str:
    return str(v)


def build_args(action: str, inv: int | None, p: dict) -> tuple[list[str], bool, str]:
    """Whitelisted action -> (CLI args, processes the task queue?, label)."""
    def need_inv() -> str:
        if inv is None:
            raise JobError(f"{action} needs an investigation")
        return str(inv)

    def flag(name: str, value) -> list[str]:
        return [name, _s(value)] if value not in (None, "", []) else []

    a: list[str]
    match action:
        case "run":
            a = ["run", need_inv(), *flag("--extract-role", p.get("extract_role"))]
            if p.get("no_screenshots"):
                a.append("--no-screenshots")
            return a, True, "Run collection and extraction"
        case "resume":
            a = ["resume", need_inv()] + (["--retry-failed"] if p.get("retry_failed") else [])
            return a, True, "Resume" + (" (retry failed)" if p.get("retry_failed") else "")
        case "refresh":
            return ["refresh", need_inv(), *flag("--since", p.get("since"))], True, "Refresh sources"
        case "enrich":
            return (["enrich", need_inv(), *flag("--enrichers", ",".join(p.get("enrichers") or []))],
                    True, "Enrich entities")
        case "reextract":
            return (["reextract", need_inv(), "--role", _s(p.get("role") or "agent_heavy")],
                    True, f"Re-extract with {p.get('role') or 'agent_heavy'}")
        case "plan":
            return (["plan", need_inv(), "--run"] if p.get("run") else ["plan", need_inv()],
                    bool(p.get("run")), "Claude: plan collection")
        case "analyze":
            return ["analyze", need_inv()] + (["--fresh"] if p.get("fresh") else []), False, \
                "Claude: analyze"
        case "assess":
            return ["assess", need_inv()] + (["--fresh"] if p.get("fresh") else []), False, \
                "Claude: threat assessment"
        case "red_team":
            return ["red-team", need_inv()], False, "Claude: red team"
        case "report":
            return ["report", need_inv()], False, "Claude: write report"
        case "ask":
            q = (p.get("question") or "").strip()
            if not q:
                raise JobError("ask needs a question")
            return ["ask", need_inv(), q], False, f"Claude: {q[:60]}"
        case "link":
            return ["link", need_inv()], False, "Claude: confirm cross-links"
        case "corroborate":
            return ["corroborate", *([str(inv)] if inv else [])], False, "Corroborate"
        case "er":
            return ["er", *([str(inv)] if inv else [])], False, "Entity resolution"
        case "export":
            fmts = ",".join(p.get("formats") or ["stix"])
            return ["export", need_inv(), "--format", fmts], False, f"Export {fmts}"
        case "bundle":
            a = ["evidence", "bundle", need_inv(), *flag("--report", p.get("report_id"))]
            if p.get("redact_faces"):
                a.append("--redact-faces")
            return a, False, "Evidence bundle"
        case "purge":
            reason = (p.get("reason") or "").strip()
            if not reason or not p.get("artifact_id"):
                raise JobError("purge needs an artifact id and a reason")
            return (["evidence", "purge", _s(int(p["artifact_id"])), "--reason", reason, "--yes"],
                    False, f"Purge artifact {p['artifact_id']}")
        case "retract":
            reason = (p.get("reason") or "").strip()
            if not reason or not p.get("relation_id"):
                raise JobError("retract needs a relation id and a reason")
            return (["retract", _s(int(p["relation_id"])), "--reason", reason], False,
                    f"Retract relation {p['relation_id']}")
        case "revise":
            if not p.get("finding_id") or not (p.get("reason") or "").strip():
                raise JobError("revise needs a finding id and a reason")
            a = ["revise", _s(int(p["finding_id"])), "--reason", p["reason"].strip(), "--by",
                 "human:ui"]
            if p.get("withdraw"):
                a.append("--withdraw")
            elif p.get("confidence") is not None:
                a += ["--confidence", _s(float(p["confidence"]))]
            return a, False, f"Revise finding {p['finding_id']}"
        case "seal":
            return ["evidence", "seal"], False, "Seal evidence"
        case "verify":
            return ["evidence", "verify"], False, "Verify evidence"
        case "graph_sync":
            return ["graph-sync"], False, "Sync graph"
        case "snapshot":
            return ["snapshot"], False, "Snapshot"
        case "daemon_once":
            return ["daemon", "--once"], False, "Run due schedules"
        case "tor_start":
            return ["tor", "start"], False, "Start Tor"
        case "tor_stop":
            return ["tor", "stop"], False, "Stop Tor"
    raise JobError(f"unknown action {action!r}")


class JobManager:
    def __init__(self, data_dir: Path, cwd: Path | None = None) -> None:
        self.dir = Path(data_dir) / "ui-jobs"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cwd = cwd or Path.cwd()
        self.grace_s = 90.0                 # a task in flight may need a while to wind down
        self._lock = threading.Lock()
        self._procs: dict[int, subprocess.Popen] = {}
        self.jobs: dict[int, Job] = {}
        # investigation id -> who else is processing its queue (e.g. a terminal run), or None
        self.busy_check: Callable[[int], str | None] | None = None
        self._load()

    # ------------------------------------------------------------------ persistence

    def _index(self) -> Path:
        return self.dir / "jobs.json"

    def _load(self) -> None:
        try:
            raw = json.loads(self._index().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = []
        for j in raw:
            job = Job(**j)
            if job.status == "running":       # the GUI restarted: we no longer own it
                job.status = "lost"
            self.jobs[job.id] = job

    def _save(self) -> None:
        rows = [asdict(j) for j in sorted(self.jobs.values(), key=lambda j: j.id)][-500:]
        self._index().write_text(json.dumps(rows, indent=1), encoding="utf-8")

    def log_path(self, job_id: int) -> Path:
        return self.dir / f"{job_id}.log"

    def stop_path(self, job_id: int) -> Path:
        return self.dir / f"{job_id}.stop"

    # ------------------------------------------------------------------ lifecycle

    def start(self, action: str, investigation_id: int | None, params: dict | None = None) -> Job:
        args, queue_worker, label = build_args(action, investigation_id, params or {})
        with self._lock:
            self._reap()
            if queue_worker and investigation_id is not None:
                busy = [j for j in self.jobs.values() if j.status == "running"
                        and j.queue_worker and j.investigation_id == investigation_id]
                if busy:
                    raise JobError(f"job {busy[0].id} ({busy[0].label}) is already processing "
                                   "this investigation's queue; wait for it or cancel it")
                holder = self.busy_check(investigation_id) if self.busy_check else None
                if holder:
                    raise JobError(f"this investigation is already being processed by {holder} "
                                   "(started outside the GUI, e.g. in a terminal); wait for it "
                                   "or stop it there with Ctrl+C")
            job = Job(id=max(self.jobs, default=0) + 1, action=action, label=label, args=args,
                      investigation_id=investigation_id, queue_worker=queue_worker)
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1", "TERM": "dumb",
                   "COLUMNS": "140", "PYTHONUNBUFFERED": "1",
                   "OSINT_STOP_FILE": str(self.stop_path(job.id))}
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            log = open(self.log_path(job.id), "wb")  # noqa: SIM115 - owned by the process
            log.write(f"$ osint {' '.join(args)}\n".encode())
            log.flush()
            proc = subprocess.Popen([sys.executable, "-m", "osint", *args], cwd=self.cwd,
                                    stdout=log, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, env=env, creationflags=flags,
                                    start_new_session=sys.platform != "win32")
            log.close()
            job.pid = proc.pid
            self._procs[job.id] = proc
            self.jobs[job.id] = job
            self._save()
            return job

    def _reap(self) -> None:
        changed = False
        for jid, proc in list(self._procs.items()):
            code = proc.poll()
            if code is None:
                continue
            job = self.jobs[jid]
            if job.status == "running":
                job.status = "done" if code == 0 else "failed"
            job.exit_code = code
            job.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
            del self._procs[jid]
            changed = True
        if changed:
            self._save()

    def list(self, investigation_id: int | None = None, limit: int = 100) -> list[dict]:
        with self._lock:
            self._reap()
            rows = [asdict(j) for j in sorted(self.jobs.values(), key=lambda j: -j.id)
                    if investigation_id is None or j.investigation_id == investigation_id]
        return rows[:limit]

    def get(self, job_id: int, tail: int = 200_000) -> dict:
        with self._lock:
            self._reap()
            job = self.jobs.get(job_id)
        if job is None:
            raise JobError(f"no job {job_id}")
        path = self.log_path(job_id)
        text = ""
        if path.exists():
            data = path.read_bytes()
            text = data[-tail:].decode("utf-8", "replace")
        return {**asdict(job), "log": text}

    def cancel(self, job_id: int) -> dict:
        with self._lock:
            proc = self._procs.get(job_id)
            job = self.jobs.get(job_id)
            if job is None or proc is None or proc.poll() is not None:
                raise JobError(f"job {job_id} is not running")
            job.status = "cancelled"
            self._save()
        self.stop_path(job_id).write_text("stop", encoding="utf-8")   # graceful: like Ctrl+C

        def hard_stop() -> None:
            time.sleep(self.grace_s)
            if proc.poll() is None:
                if sys.platform == "win32":       # the venv launcher has a child: kill the tree
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   capture_output=True, check=False)
                else:
                    os.killpg(proc.pid, signal.SIGKILL)

        threading.Thread(target=hard_stop, daemon=True).start()
        return asdict(job)

    def active(self) -> int:
        with self._lock:
            self._reap()
            return sum(1 for j in self.jobs.values() if j.status == "running")
