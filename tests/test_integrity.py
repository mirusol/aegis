from aegis.config import AegisConfig
from aegis.core import integrity
from aegis.core.baseline import build_baseline
from aegis.core.database import Database


def _cfg(tmp_path, **kw):
    watch = tmp_path / "w"
    watch.mkdir()
    (watch / "a.txt").write_text("alpha")
    cfg = AegisConfig(database_path=str(tmp_path / "db.sqlite"), paths=[str(watch)], **kw)
    return cfg, watch


def test_build_baseline_sets_seal(tmp_path):
    cfg, _ = _cfg(tmp_path)
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    assert integrity.verify_seal(db, None).status == "ok"


def test_external_tamper_is_detected(tmp_path):
    """If someone edits a hash directly in the DB, the seal no longer matches."""
    cfg, _ = _cfg(tmp_path)
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    with db.connect() as conn:
        conn.execute("UPDATE files SET hash = 'deadbeef'")
    assert integrity.verify_seal(db, None).status == "tampered"


def test_hmac_key_protects_seal(tmp_path):
    cfg, _ = _cfg(tmp_path, integrity_key="secret")
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    assert integrity.verify_seal(db, "secret").status == "ok"
    # without the correct key the HMAC seal cannot be reproduced -> looks tampered
    assert integrity.verify_seal(db, "wrong-key").status == "tampered"


def test_unset_when_no_baseline(tmp_path):
    cfg, _ = _cfg(tmp_path)
    db = Database(cfg.database_path)
    db.init_schema()
    assert integrity.verify_seal(db, None).status == "unset"
