import hashlib
import io
import os
import stat

import pytest

from osint.storage.raw_store import IntegrityError, RawStore


def test_put_is_content_addressed_and_idempotent(raw_store: RawStore):
    data = b"evidence bytes"
    ref = raw_store.put_bytes(data)
    assert ref.sha256 == hashlib.sha256(data).hexdigest()
    assert ref.sha512 == hashlib.sha512(data).hexdigest()
    assert ref.path == f"raw/{ref.sha256[:2]}/{ref.sha256[2:4]}/{ref.sha256}"
    assert raw_store.put_bytes(data) == ref
    assert raw_store.put_stream(io.BytesIO(data)) == ref
    assert raw_store.read_bytes(ref.sha256) == data
    assert list(raw_store.iter_digests()) == [ref.sha256]
    assert not any(p.name.startswith(".incoming") for p in raw_store.root.iterdir())


def test_stored_files_are_read_only(raw_store: RawStore):
    ref = raw_store.put_bytes(b"x")
    mode = os.stat(raw_store.path_for(ref.sha256)).st_mode
    assert not mode & stat.S_IWRITE


def test_verify_detects_tampering(raw_store: RawStore):
    ref = raw_store.put_bytes(b"original")
    raw_store.verify(ref.sha256, ref.sha512)
    path = raw_store.path_for(ref.sha256)
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        raw_store.verify(ref.sha256)


def test_missing_and_bad_digest(raw_store: RawStore):
    with pytest.raises(IntegrityError):
        raw_store.verify("0" * 64)
    with pytest.raises(ValueError):
        raw_store.path_for("../../etc/passwd")


def test_purge(raw_store: RawStore):
    ref = raw_store.put_bytes(b"to purge")
    raw_store.purge(ref.sha256)
    assert not raw_store.exists(ref.sha256)
