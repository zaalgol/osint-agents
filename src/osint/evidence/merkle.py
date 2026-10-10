"""Merkle trees over custody entry hashes (RFC 6962-style domain separation).

leaf = SHA256(0x00 || entry_hash_bytes), node = SHA256(0x01 || left || right); an odd
node is promoted unchanged to the next level. An inclusion proof is the list of sibling
hashes (with side) from a leaf to the root.
"""

from __future__ import annotations

import hashlib

LEAF = bytes([0])
NODE = bytes([1])


def leaf_hash(entry_hash_hex: str) -> bytes:
    return hashlib.sha256(LEAF + bytes.fromhex(entry_hash_hex)).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE + left + right).digest()


def levels(entry_hashes: list[str]) -> list[list[bytes]]:
    if not entry_hashes:
        raise ValueError("empty tree")
    level = [leaf_hash(h) for h in entry_hashes]
    out = [level]
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
               for i in range(0, len(level), 2)]
        out.append(nxt)
        level = nxt
    return out


def root(entry_hashes: list[str]) -> str:
    return levels(entry_hashes)[-1][0].hex()


def proof(entry_hashes: list[str], index: int) -> list[list[str]]:
    """[[side, sibling_hex], ...] where side is 'L' if the sibling is on the left."""
    path = []
    for level in levels(entry_hashes)[:-1]:
        sib = index ^ 1
        if sib < len(level):
            path.append(["L" if sib < index else "R", level[sib].hex()])
        index //= 2
    return path


def verify_proof(entry_hash_hex: str, path: list[list[str]], expected_root: str) -> bool:
    h = leaf_hash(entry_hash_hex)
    for side, sib in path:
        h = node_hash(bytes.fromhex(sib), h) if side == "L" else node_hash(h, bytes.fromhex(sib))
    return h.hex() == expected_root
