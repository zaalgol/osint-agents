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


class BlockedContent(RuntimeError):
    """Content whose hash is on a blocklist (known CSAM/malware/purged): never stored."""

    def __init__(self, sha256: str, list_name: str) -> None:
        super().__init__(f"content {sha256[:16]}... is on blocklist {list_name}; not stored")
        self.sha256 = sha256
        self.list_name = list_name


HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


class Blocklist:
    """Known-bad content hashes in <data_dir>/blocklists/*.txt.

    One hash per line (md5, sha1 or sha256 hex, detected by length; an optional
    "algo:" prefix is accepted). Text after '#' is a comment. Files are re-read when
    they change, so dropping in a list (e.g. one provided by a hotline or a malware
    feed) takes effect without a restart. `purge` appends to purged.txt.
    """

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self._sig: tuple | None = None
        self._hashes: dict[str, str] = {}      # hex digest -> list file name

    def _load(self) -> None:
        files = sorted(self.dir.glob("*.txt")) if self.dir.is_dir() else []
        sig = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        if sig == self._sig:
            return
        hashes: dict[str, str] = {}
        for p in files:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                tok = line.split("#", 1)[0].strip().lower()
                tok = tok.split(":", 1)[-1].strip()
                if len(tok) in HASH_LENGTHS and all(c in "0123456789abcdef" for c in tok):
                    hashes.setdefault(tok, p.name)
        self._hashes, self._sig = hashes, sig

    def __len__(self) -> int:
        self._load()
        return len(self._hashes)

    def match(self, *digests: str) -> str | None:
        self._load()
        return next((self._hashes[d] for d in digests if d in self._hashes), None)

    def check(self, data: bytes) -> None:
        if not len(self):
            return
        sha256 = hashlib.sha256(data).hexdigest()
        hit = self.match(sha256, hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest())
        if hit:
            raise BlockedContent(sha256, hit)

    def add(self, sha256: str, note: str = "", list_name: str = "purged.txt") -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with open(self.dir / list_name, "a", encoding="utf-8") as f:
            f.write(f"{sha256}" + (f"  # {note}" if note else "") + "\n")


class RawStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.root = self.data_dir / "raw"
        self.blocklist = Blocklist(self.data_dir / "blocklists")

    def path_for(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError(f"not a sha256 hex digest: {sha256!r}")
        return self.root / sha256[:2] / sha256[2:4] / sha256

    def put_bytes(self, data: bytes) -> BlobRef:
        self.blocklist.check(data)               # in memory: blocked bytes never touch disk
        return self.put_chunks([data])

    def put_file(self, src: Path) -> BlobRef:
        with open(src, "rb") as f:
            return self.put_stream(f)

    def put_stream(self, stream: BinaryIO) -> BlobRef:
        return self.put_chunks(iter(lambda: stream.read(CHUNK), b""))

    def put_chunks(self, chunks: Iterable[bytes]) -> BlobRef:
        self.root.mkdir(parents=True, exist_ok=True)
        h256, h512, size = hashlib.sha256(), hashlib.sha512(), 0
        md5, sha1 = hashlib.md5(), hashlib.sha1()
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".incoming-")
        try:
            with os.fdopen(fd, "wb") as out:
                for chunk in chunks:
                    h256.update(chunk)
                    h512.update(chunk)
                    md5.update(chunk)
                    sha1.update(chunk)
                    size += len(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            digest = h256.hexdigest()
            hit = self.blocklist.match(digest, md5.hexdigest(), sha1.hexdigest())
            if hit:
                raise BlockedContent(digest, hit)  # the temp file is removed below
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
