"""Content-addressed, write-once store for raw evidence.

Layout: <data_dir>/raw/<ab>/<cd>/<sha256>. A file's name is its own SHA-256, so
storing is idempotent and integrity is checked by re-hashing. Files are written
atomically and then made read-only. Their content is never modified afterwards.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO

from osint.core.models import BlobRef

CHUNK = 1 << 20


class IntegrityError(RuntimeError):
    pass


class RawStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.root = self.data_dir / "raw"

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError(f"not a sha256 hex digest: {sha256!r}")
        return self.root / sha256[:2] / sha256[2:4] / sha256

    def put_bytes(self, data: bytes) -> BlobRef:
        return self.put_chunks([data])

    def put_file(self, src: Path) -> BlobRef:
        with open(src, "rb") as f:
            return self.put_stream(f)

    def put_stream(self, stream: BinaryIO) -> BlobRef:
        return self.put_chunks(iter(lambda: stream.read(CHUNK), b""))

    def put_chunks(self, chunks: Iterable[bytes]) -> BlobRef:
        self.root.mkdir(parents=True, exist_ok=True)
        h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".incoming-")
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in chunks:
                    h256.update(chunk)
                    h512.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            digest = h256.hexdigest()
            dest = self.path_for(digest)
            if dest.exists():
                os.unlink(tmp)  # already stored, so this put is a no-op
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                os.replace(tmp, dest)
                os.chmod(dest, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return BlobRef(
            sha256=digest,
            sha512=h512.hexdigest(),
            size=size,
            path=dest.relative_to(self.data_dir).as_posix(),
        )

    def exists(self, sha256: str) -> bool:
        return self.path_for(sha256).is_file()

    def open(self, sha256: str) -> BinaryIO:
        return open(self.path_for(sha256), "rb")

    def read_bytes(self, sha256: str) -> bytes:
        return self.path_for(sha256).read_bytes()

    def verify(self, sha256: str, sha512: str | None = None) -> None:
        """Re-hash a stored blob; raise IntegrityError if it doesn't match."""
        path = self.path_for(sha256)
        if not path.is_file():
            raise IntegrityError(f"missing blob {sha256}")
        h256, h512 = hashlib.sha256(), hashlib.sha512()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK), b""):
                h256.update(chunk)
                h512.update(chunk)
        if h256.hexdigest() != sha256:
            raise IntegrityError(f"sha256 mismatch for {path}")
        if sha512 is not None and h512.hexdigest() != sha512:
            raise IntegrityError(f"sha512 mismatch for {path}")

    def iter_digests(self) -> Iterable[str]:
        if not self.root.is_dir():
            return
        for p in self.root.glob("??/??/*"):
            if p.is_file():
                yield p.name

    def purge(self, sha256: str) -> None:
        """Hard-delete a blob (contamination/CSAM procedure only). Caller must log custody."""
        path = self.path_for(sha256)
        if path.exists():
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            path.unlink()
