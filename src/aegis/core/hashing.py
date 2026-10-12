from __future__ import annotations

import hashlib

DEFAULT_ALGORITHM = "sha256"
DEFAULT_CHUNK_SIZE = 65536


def hash_file(path: str, algorithm: str = DEFAULT_ALGORITHM,
              chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Return the hex digest of a file."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
