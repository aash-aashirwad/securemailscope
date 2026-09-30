"""Evidence-integrity hashing (P0/P2: evidence integrity hashes, chain of
custody support). SHA-256 is computed over the raw uploaded capture and
over generated report files so a later export can be proven to match
what was originally analyzed."""
import hashlib


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
