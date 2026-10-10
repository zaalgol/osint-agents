"""Standalone verifier for an osint evidence bundle (copied into every bundle as verify.py).

Python 3.10+ standard library only. Optional: the `cryptography` package (signature check)
and the `openssl` / `ots` command-line tools (timestamp checks).

    python verify.py            # run inside the unzipped bundle directory

Checks:
  1. every file's SHA-256 matches bundle.json
  2. every artifact's raw file hash matches its custody "captured" entry
  3. every custody entry hash recomputes from its fields and previous hash
  4. every custody entry is included (Merkle proof) in a sealed manifest
  5. each manifest's digest recomputes; Ed25519 signature (if `cryptography` is present)
  6. RFC 3161 tokens: `openssl ts -verify` against the TSA certificates (if openssl exists)
  7. OpenTimestamps: lists the .ots files to check with `ots verify` (Bitcoin-anchored)
"""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

LEAF, NODE = bytes([0]), bytes([1])
OK, BAD = "OK  ", "FAIL"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def entry_hash(e: dict) -> str:
    payload = canonical_json({"artifact_id": e["artifact_id"], "action": e["action"],
                              "actor": e["actor"], "at_utc": e["at_utc"],
                              "details": e["details"]})
    return hashlib.sha256((e["prev_hash"] + payload).encode("utf-8")).hexdigest()


def merkle_ok(leaf_hex: str, path: list, root: str) -> bool:
    h = hashlib.sha256(LEAF + bytes.fromhex(leaf_hex)).digest()
    for side, sib in path:
        s = bytes.fromhex(sib)
        h = hashlib.sha256(NODE + (s + h if side == "L" else h + s)).digest()
    return h.hex() == root


def main(root: Path) -> int:
    meta = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
    failures = 0

    def report(ok: bool, msg: str) -> None:
        nonlocal failures
        failures += 0 if ok else 1
        print(f"[{OK if ok else BAD}] {msg}")

    print(f"bundle: {meta['title']}  (created {meta['created_at']})\n")

    for rel, digest in meta["files"].items():
        p = root / rel
        report(p.exists() and sha256_file(p) == digest, f"file hash  {rel}")

    entries = {e["seq"]: e for e in meta["custody"]}
    for e in entries.values():
        report(entry_hash(e) == e["entry_hash"], f"custody #{e['seq']} {e['action']} recomputes")

    for art in meta["artifacts"]:
        captured = [e for e in entries.values()
                    if e["artifact_id"] == art["id"] and e["action"] == "captured"]
        raw_ok = bool(captured) and captured[0]["details"].get("sha256") == art["sha256"] \
            and sha256_file(root / art["raw_path"]) == art["sha256"]
        report(raw_ok, f"artifact A:{art['id']} raw file matches its custody 'captured' entry")

    manifests = {}
    for m in meta["manifests"]:
        doc = json.loads((root / m["path"]).read_text(encoding="utf-8"))
        body = doc["manifest"]
        digest = hashlib.sha256(canonical_json(body).encode("utf-8")).digest()
        manifests[m["id"]] = (body, digest)
        report(digest.hex() == doc["digest_sha256"], f"manifest {m['id']} digest recomputes")
        try:
            from cryptography.hazmat.primitives import serialization

            pub = serialization.load_pem_public_key(doc["public_key_pem"].encode())
            try:
                pub.verify(bytes.fromhex(doc["signature_ed25519"]), digest)
                report(True, f"manifest {m['id']} Ed25519 signature (key {doc['key_id']})")
            except Exception:  # noqa: BLE001
                report(False, f"manifest {m['id']} Ed25519 signature")
        except ImportError:
            print(f"[SKIP] manifest {m['id']} signature (pip install cryptography to check)")

        for ts in m.get("timestamps", []):
            p = root / ts["path"]
            if ts["method"] == "rfc3161":
                committed = p.exists() and digest in p.read_bytes()
                report(committed, f"manifest {m['id']} RFC 3161 token contains the digest")
                ca, tsa = root / ts.get("cacert", ""), root / ts.get("tsacert", "")
                if shutil.which("openssl") and ca.is_file() and tsa.is_file():
                    r = subprocess.run(["openssl", "ts", "-verify", "-digest", digest.hex(),
                                        "-in", str(p), "-CAfile", str(ca), "-untrusted",
                                        str(tsa)], capture_output=True, text=True, check=False)
                    report("Verification: OK" in r.stdout + r.stderr,
                           f"manifest {m['id']} RFC 3161 token signature (openssl, {ts['authority']})")
                else:
                    print("[SKIP] RFC 3161 signature check (needs openssl + TSA certs)")
            else:
                print(f"[INFO] OpenTimestamps proof {ts['path']}: run `ots upgrade` then "
                      f"`ots verify -d {digest.hex()} {ts['path']}` (Bitcoin-anchored)")

    for e in entries.values():
        inc = e.get("inclusion")
        if not inc:
            report(False, f"custody #{e['seq']} is not covered by a sealed manifest")
            continue
        body, _ = manifests[inc["manifest_id"]]
        report(merkle_ok(e["entry_hash"], inc["path"], body["merkle_root"]),
               f"custody #{e['seq']} included in manifest {inc['manifest_id']}")

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent))
