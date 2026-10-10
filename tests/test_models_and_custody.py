from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from osint.core.config import Settings
from osint.core.models import Citation, EpistemicStatus, FindingIn, PremiseType
from osint.evidence.custody import GENESIS, compute_entry_hash


def test_citation_needs_quote_or_locator():
    Citation(artifact_id=1, quote_original="text")
    Citation(artifact_id=1, media_locator="00:03:12")
    with pytest.raises(ValidationError):
        Citation(artifact_id=1)
    with pytest.raises(ValidationError):
        Citation(artifact_id=1, quote_original="x", char_start=5)
    with pytest.raises(ValidationError):
        Citation(artifact_id=1, quote_original="x", char_start=5, char_end=2)


def _finding(**kw):
    base = {"investigation_id": 1, "kind": "fact", "text": "t", "confidence": 0.7, "created_by": "test"}
    return FindingIn(**{**base, **kw})


def test_finding_requires_proof():
    _finding(epistemic_status=EpistemicStatus.OBSERVED,
             citations=[Citation(artifact_id=1, quote_original="q")])
    with pytest.raises(ValidationError, match="no claim without proof"):
        _finding(epistemic_status=EpistemicStatus.OBSERVED)
    with pytest.raises(ValidationError, match="proof tree"):
        _finding(epistemic_status=EpistemicStatus.INFERRED,
                 citations=[Citation(artifact_id=1, quote_original="q")])
    with pytest.raises(ValidationError, match="method"):
        _finding(epistemic_status=EpistemicStatus.ASSESSED,
                 premises=[(PremiseType.EVIDENCE, 1)])
    _finding(epistemic_status=EpistemicStatus.INFERRED,
             premises=[(PremiseType.EVIDENCE, 1)], method="shared wallet")


def test_custody_hash_covers_every_field():
    at = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
    base = {"prev_hash": GENESIS, "artifact_id": 1, "action": "captured", "actor": "a",
                "at_utc": at, "details": {"k": 1}}
    h = compute_entry_hash(**base)
    assert h == compute_entry_hash(**base)
    for change in ({"prev_hash": "1" * 64}, {"artifact_id": 2}, {"action": "parsed"},
                   {"actor": "b"}, {"at_utc": at + timedelta(microseconds=1)},
                   {"details": {"k": 2}}):
        assert compute_entry_hash(**{**base, **change}) != h


def test_custody_hash_is_timezone_normalized():
    utc = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
    local = utc.astimezone(timezone(timedelta(hours=3)))
    args = {"prev_hash": GENESIS, "artifact_id": None, "action": "x", "actor": "y", "details": {}}
    assert compute_entry_hash(at_utc=utc, **args) == compute_entry_hash(at_utc=local, **args)
    with pytest.raises(ValueError):
        compute_entry_hash(at_utc=datetime(2026, 1, 1), **args)


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("OSINT_POSTGRES__PORT", "6543")
    s = Settings()
    assert s.postgres.port == 6543
    assert s.postgres.url.endswith(":6543/osint")
