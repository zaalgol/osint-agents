"""Analyst jobs: plan, analyze, report (+ automatic citation audit), ask.

The cache fingerprint covers the investigation's knowledge state (counts and max ids of
evidence, findings and reports). Re-running a job on an unchanged knowledge base returns
the cached result instead of spending subscription quota.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any

from sqlalchemy import func, select

from osint.core.config import project_home
from osint.core.context import App
from osint.llm.claude_cli import ClaudeResult, ClaudeRunner
from osint.reports.render import render_report
from osint.storage.db import EvidenceLink, Finding, Investigation, InvestigationRef, Report


def load_prompt(name: str, **values: Any) -> str:
    text = (project_home() / "prompts" / f"{name}.md").read_text(encoding="utf-8")
    return Template(text).safe_substitute({k: str(v) for k, v in values.items()})


def fingerprint(app: App, inv_id: int) -> str:
    with app.session_factory() as s:
        refs = s.execute(select(InvestigationRef.object_type, func.count(),
                                func.max(InvestigationRef.object_id))
                         .where(InvestigationRef.investigation_id == inv_id)
                         .group_by(InvestigationRef.object_type)).all()
        f = s.execute(select(func.count(), func.max(Finding.id)).where(
            Finding.investigation_id == inv_id)).one()
        r = s.execute(select(func.count(), func.max(Report.id)).where(
            Report.investigation_id == inv_id)).one()
        e = s.scalar(select(func.max(EvidenceLink.id)))
    return json.dumps({"refs": sorted(map(list, refs)), "findings": list(f), "reports": list(r),
                       "evidence_max": e}, default=str)


@dataclass
class JobOutcome:
    result: ClaudeResult
    extra: dict[str, Any]


class Analyst:
    def __init__(self, app: App, runner: ClaudeRunner | None = None):
        self.app = app
        self.runner = runner or ClaudeRunner(app)
        self.system = load_prompt("analyst_system")

    def _inv(self, inv_id: int) -> Investigation:
        with self.app.session_factory() as s:
            inv = s.get(Investigation, inv_id)
            if inv is None:
                raise ValueError(f"no investigation {inv_id}")
            s.expunge(inv)
            return inv

    def _turns(self, job: str, default: int) -> int:
        return self.runner.cfg.max_turns.get(job, default)

    # ------------------------------------------------------------------ jobs

    def plan(self, inv_id: int, max_requests: int = 12, fresh: bool = False) -> JobOutcome:
        inv = self._inv(inv_id)
        prompt = load_prompt("plan_investigation", investigation_name=inv.name,
                             investigation_id=inv.id, max_requests=max_requests,
                             seed=json.dumps(inv.seed or {}, ensure_ascii=False, indent=2))
        res = self.runner.run("plan_investigation", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=max_requests,
                              max_turns=self._turns("plan_investigation", 25), fresh=fresh)
        if res.data:
            with self.app.session_factory() as s, s.begin():
                row = s.get(Investigation, inv.id)
                row.config = {**(row.config or {}), "plan": res.data}
        return JobOutcome(res, {"plan": res.data})

    def analyze(self, inv_id: int, max_requests: int = 10, fresh: bool = False) -> JobOutcome:
        inv = self._inv(inv_id)
        plan = (inv.config or {}).get("plan") or {}
        with self.app.session_factory() as s:
            n_findings = s.scalar(select(func.count()).where(Finding.investigation_id == inv.id))
        prompt = load_prompt(
            "analyze_investigation", investigation_name=inv.name, investigation_id=inv.id,
            focus=(inv.seed or {}).get("focus") or inv.name, max_requests=max_requests,
            questions="\n".join(f"- {q}" for q in plan.get("questions", [])) or "(none)",
            finding_count=n_findings)
        res = self.runner.run("analyze_investigation", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=max_requests,
                              max_turns=self._turns("analyze_investigation", 60), fresh=fresh)
        return JobOutcome(res, {})

    def red_team(self, inv_id: int, max_requests: int = 5, fresh: bool = False) -> JobOutcome:
        inv = self._inv(inv_id)
        with self.app.session_factory() as s:
            n = s.scalar(select(func.count()).where(Finding.investigation_id == inv.id))
        if not n:
            return JobOutcome(None, {"skipped": "no findings to challenge (run analyze first)"})
        prompt = load_prompt("red_team", investigation_name=inv.name, investigation_id=inv.id,
                             finding_count=n, max_requests=max_requests)
        res = self.runner.run("red_team", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=max_requests,
                              max_turns=self._turns("red_team", 40), fresh=fresh)
        applied = self.apply_red_team(res.job_id)
        return JobOutcome(res, {"revisions": applied})

    def apply_red_team(self, job_id: int) -> list[dict]:
        """Turn a red-team job's suggested confidences into revisions (same policy as the
        tool: downgrades apply, anything else goes to review). Skips findings that already
        have a revision from this job."""
        import re

        from osint.analyst.revisions import RevisionError, propose_revision
        from osint.storage.db import ClaudeJob, FindingRevision

        out = []
        with self.app.session_factory() as s:
            job = s.get(ClaudeJob, job_id)
            data = (job.result_json if job else None) or {}
            inv_id = job.investigation_id if job else None
        actor = f"claude:red_team#{job_id}"
        for c in data.get("challenged", []):
            m = re.search(r"F:(\d+)", str(c.get("finding", "")))
            conf = c.get("suggested_confidence")
            if not m or not isinstance(conf, int | float):
                continue
            fid = int(m.group(1))
            try:
                with self.app.session_factory() as s, s.begin():
                    if s.scalar(select(FindingRevision.id).where(
                            FindingRevision.finding_id == fid,
                            FindingRevision.proposed_by == actor)):
                        continue
                    out.append(propose_revision(
                        s, fid, float(conf), f"red team: {c.get('issue', '')}", actor,
                        auto_apply_downgrades=self.app.settings.analysis.auto_apply_downgrades,
                        investigation_id=inv_id))
            except RevisionError as e:
                out.append({"finding": f"[F:{fid}]", "skipped": str(e)})
        return out

    def threat_assessment(self, inv_id: int, fresh: bool = False) -> JobOutcome:
        inv = self._inv(inv_id)
        prompt = load_prompt("threat_assessment", investigation_name=inv.name,
                             investigation_id=inv.id,
                             focus=(inv.seed or {}).get("focus") or inv.name)
        res = self.runner.run("threat_assessment", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=0,
                              max_turns=self._turns("threat_assessment", 50), fresh=fresh)
        return JobOutcome(res, {})

    def red_team_current(self, inv_id: int) -> bool:
        """Has a red-team pass run after the most recent analysis/assessment?"""
        from osint.storage.db import ClaudeJob

        with self.app.session_factory() as s:
            def last(job: str):
                return s.scalar(select(func.max(ClaudeJob.finished_at)).where(
                    ClaudeJob.investigation_id == inv_id, ClaudeJob.job == job,
                    ClaudeJob.status == "done"))
            rt = last("red_team")
            analysis = max((t for t in (last("analyze_investigation"),
                                        last("threat_assessment")) if t), default=None)
        return rt is not None and (analysis is None or rt >= analysis)

    def report(self, inv_id: int, audience: str = "security analysts and decision makers",
               audit: bool = True, fresh: bool = False) -> JobOutcome:
        inv = self._inv(inv_id)
        prompt = load_prompt("report", investigation_name=inv.name, investigation_id=inv.id,
                             audience=audience,
                             focus=(inv.seed or {}).get("focus") or inv.name)
        res = self.runner.run("report", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=0,
                              max_turns=self._turns("report", 50), fresh=fresh)
        report = self.latest_report(inv.id)
        if report is None:
            return JobOutcome(res, {"report_id": None})
        audits = 0
        while audit and report.status == "draft" and audits < 2:
            audits += 1
            self.citation_audit(inv.id, report.id)
            newer = self.latest_report(inv.id)
            if newer is None or newer.id == report.id:
                break
            report = newer
        paths = self.render(report.id)
        return JobOutcome(res, {"report_id": report.id, "status": report.status,
                                "audits": audits, "paths": {k: str(v) for k, v in paths.items()},
                                "verification": (report.verification or {}).get("summary")})

    def citation_audit(self, inv_id: int, report_id: int) -> JobOutcome:
        inv = self._inv(inv_id)
        with self.app.session_factory() as s:
            r = s.get(Report, report_id)
            issues = [c for c in (r.verification or {}).get("checks", []) if c.get("issues")]
            md_text = r.markdown
        prompt = load_prompt("citation_audit", report_id=report_id, investigation_name=inv.name,
                             issues=json.dumps(issues[:60], ensure_ascii=False, indent=1),
                             markdown=md_text)
        res = self.runner.run("citation_audit", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id), max_requests=0,
                              max_turns=self._turns("citation_audit", 30))
        return JobOutcome(res, {})

    def link(self, inv_id: int, fresh: bool = False) -> JobOutcome:
        from osint.storage.db import CrossLink

        inv = self._inv(inv_id)
        with self.app.session_factory() as s:
            n = s.scalar(select(func.count()).where(
                CrossLink.status == "candidate",
                (CrossLink.investigation_a == inv.id) | (CrossLink.investigation_b == inv.id)))
        if not n:
            return JobOutcome(None, {"candidates": 0})
        prompt = load_prompt("link_investigations", investigation_name=inv.name,
                             investigation_id=inv.id, candidate_count=n)
        res = self.runner.run("link_investigations", inv.id, prompt, self.system,
                              fingerprint=fingerprint(self.app, inv.id) + f"|links:{n}",
                              max_requests=0, max_turns=self._turns("link_investigations", 40),
                              fresh=fresh)
        return JobOutcome(res, {"candidates": n})

    def ask(self, inv_id: int, question: str) -> JobOutcome:
        inv = self._inv(inv_id)
        prompt = load_prompt("ask", investigation_name=inv.name, investigation_id=inv.id,
                             question=question)
        res = self.runner.run("ask", inv.id, prompt, self.system, toolset="read",
                              fingerprint=fingerprint(self.app, inv.id), max_requests=0,
                              max_turns=self._turns("ask", 20))
        return JobOutcome(res, {})

    # ------------------------------------------------------------------ helpers

    def latest_report(self, inv_id: int) -> Report | None:
        with self.app.session_factory() as s:
            r = s.scalar(select(Report).where(Report.investigation_id == inv_id)
                         .order_by(Report.id.desc()).limit(1))
            if r is not None:
                s.expunge(r)
            return r

    def render(self, report_id: int) -> dict[str, Path]:
        with self.app.session_factory() as s:
            r = s.get(Report, report_id)
            out = self.app.settings.data_path / "reports" / f"inv-{r.investigation_id}"
            return render_report(s, r, out)
