"""Web GUI backend: JSON API, CSRF on every write, whitelisted background jobs."""

from __future__ import annotations

import uuid

import pytest

from osint.ui import jobs as jobs_mod
from osint.ui.jobs import JobError, JobManager, build_args


def test_job_actions_are_whitelisted_and_validated():
    args, worker, _ = build_args("run", 3, {"extract_role": "agent_heavy", "no_screenshots": True})
    assert args == ["run", "3", "--extract-role", "agent_heavy", "--no-screenshots"] and worker
    assert build_args("ask", 3, {"question": "who? ; rm -rf /"})[0] == ["ask", "3", "who? ; rm -rf /"]
    assert build_args("purge", None, {"artifact_id": "7", "reason": "csam"})[0][-1] == "--yes"
    for action, inv, params in [("shell", 1, {}), ("ask", 1, {}), ("purge", None, {"artifact_id": 1}),
                                ("run", None, {}), ("revise", 1, {"finding_id": 2})]:
        with pytest.raises(JobError):
            build_args(action, inv, params)


class FakeProc:
    def __init__(self, *a, **kw):
        self.pid = 4242
        self.code = None
        FakeProc.last = self

    def poll(self):
        return self.code


def test_one_queue_worker_per_investigation(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs_mod.subprocess, "Popen", FakeProc)
    jm = JobManager(tmp_path)
    first = jm.start("run", 5, {})
    with pytest.raises(JobError, match="already processing"):
        jm.start("resume", 5, {})
    assert jm.start("analyze", 5, {}).id == first.id + 1      # Claude jobs don't block
    assert jm.start("run", 6, {}).queue_worker                 # other investigations do run
    FakeProc.last.code = 0
    procs = list(jm._procs.values())
    for p in procs:
        p.code = 0
    assert {j["status"] for j in jm.list()} == {"done"}
    assert jm.start("run", 5, {}).status == "running"           # free again
    assert "osint run 5" in jm.get(first.id)["log"]
    reloaded = JobManager(tmp_path)                             # GUI restart: not ours anymore
    assert {j.status for j in reloaded.jobs.values()} >= {"lost"}


@pytest.fixture
def client(pg_settings, tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from osint.core.context import App
    from osint.ui.app import create_app

    monkeypatch.setattr(jobs_mod.subprocess, "Popen", FakeProc)
    pg_settings.evidence.screenshots = False
    a = App(pg_settings)
    c = TestClient(create_app(a, jobs=JobManager(tmp_path / "jobs")))
    token = c.get("/").text.split('name="csrf" content="')[1].split('"')[0]
    c.headers.update({"origin": "http://127.0.0.1:8765"})
    return c, {"x-csrf-token": token}


@pytest.mark.integration
def test_gui_api_create_collect_profile_archive(client):
    c, csrf = client
    name = f"gui-{uuid.uuid4().hex[:6]}"
    body = {"name": name, "focus": "test", "urls": ["https://example.org/"], "run": True}
    assert c.post("/api/investigations", json=body).status_code == 403          # no token
    r = c.post("/api/investigations", json=body, headers=csrf).json()
    inv, job = r["id"], r["job"]
    assert job is not None                                                       # run started
    st = c.get(f"/api/inv/{inv}/status").json()
    assert st["name"] == name and st["tasks"]["collect"]["pending"] == 1
    assert c.post("/api/investigations", json=body, headers=csrf).status_code == 400   # duplicate

    bad = c.post(f"/api/inv/{inv}/collect", json={"plugin": "web", "params": {}}, headers=csrf)
    assert bad.status_code == 400                                                # urls required
    ok = c.post(f"/api/inv/{inv}/collect", headers=csrf,
                json={"plugin": "telegram_public", "params": {"channels": ["durov"]}})
    assert ok.status_code == 200 and ok.json()["created"]

    assert c.post(f"/api/inv/{inv}/network", json={"profile": "sneaky"}, headers=csrf).status_code == 400
    c.post(f"/api/inv/{inv}/network", json={"profile": "anonymous"}, headers=csrf)
    assert c.get(f"/api/inv/{inv}/status").json()["profile"] == "anonymous"

    r = c.post("/api/jobs", json={"action": "run", "investigation_id": inv}, headers=csrf)
    assert r.status_code == 409                                                  # one runner
    assert c.post("/api/jobs", json={"action": "shell"}, headers=csrf).status_code == 400

    c.post(f"/api/inv/{inv}/archive", json={"archived": True}, headers=csrf)
    row = next(i for i in c.get("/api/investigations").json() if i["id"] == inv)
    assert row["status"] == "archived"


@pytest.mark.integration
def test_gui_api_upload_sources_plugins_and_spa(client):
    c, csrf = client
    inv = c.post("/api/investigations", headers=csrf,
                 json={"name": f"gui-{uuid.uuid4().hex[:6]}", "urls": ["https://example.org/"]}).json()["id"]
    up = c.post(f"/api/inv/{inv}/upload", headers=csrf, data={"url": "https://src.example/x"},
                files={"file": ("note.txt", f"hello {uuid.uuid4()}".encode(), "text/plain")})
    assert up.status_code == 200 and up.json()["parse_queued"]
    ev = c.get(f"/api/inv/{inv}/evidence").json()["artifacts"]
    src = next(a["source"] for a in ev if a["id"] == up.json()["artifact"])
    assert src["locator"] == "src.example" and src["grade"] == "F"
    assert c.post(f"/api/sources/{src['id']}/grade", json={"grade": "Z"}, headers=csrf).status_code == 400
    g = c.post(f"/api/sources/{src['id']}/grade", json={"grade": "b", "note": "test"}, headers=csrf)
    assert g.json() == {"id": src["id"], "grade": "B", "note": "test"}

    plugins = {p["name"]: p for p in c.get("/api/plugins").json()}
    assert "channels" in plugins["telegram_public"]["schema"]["properties"]

    page = c.get(f"/inv/{inv}/graph")                        # client-side route -> the SPA
    assert page.status_code == 200 and 'name="csrf"' in page.text
    assert c.get("/api/nope").status_code == 404
    assert c.get("/files/..%2F..%2Fpyproject.toml").status_code == 404   # no traversal


def test_cancel_uses_the_stop_file_the_cli_watches(tmp_path, monkeypatch):
    seen = {}

    class Proc(FakeProc):
        def __init__(self, *a, **kw):
            super().__init__()
            seen["env"] = kw["env"]

    monkeypatch.setattr(jobs_mod.subprocess, "Popen", Proc)
    jm = JobManager(tmp_path)
    jm.grace_s = 3600                                   # no hard kill during the test
    job = jm.start("analyze", 1, {})
    stop = jm.stop_path(job.id)
    assert seen["env"]["OSINT_STOP_FILE"] == str(stop) and not stop.exists()
    assert jm.cancel(job.id)["status"] == "cancelled" and stop.exists()
    with pytest.raises(JobError):
        jm.cancel(999)
