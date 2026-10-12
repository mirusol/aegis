import hashlib

import pytest

from aegis.core.hashing import hash_file


def test_hash_known_content(tmp_path):
    """A file with known content must yield the known SHA-256."""
    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello")
    assert hash_file(str(f)) == hashlib.sha256(b"hello").hexdigest()


def test_hash_large_file_chunked(tmp_path):
    """The chunked hash must equal the one computed in a single pass."""
    data = b"x" * (1024 * 300)  # 300 KB, > chunk_size
    f = tmp_path / "big.bin"
    f.write_bytes(data)
    assert hash_file(str(f), chunk_size=4096) == hashlib.sha256(data).hexdigest()


def test_hash_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(str(tmp_path / "nu_exista.txt"))
