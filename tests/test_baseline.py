from aegis.config import AegisConfig
from aegis.core.baseline import build_baseline, compare_to_baseline
from aegis.core.database import Database
from aegis.core.scanner import normalize_path


def _make_config(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "a.txt").write_text("alpha")
    (watch / "b.conf").write_text("beta")
    (watch / "ignore.log").write_text("noise")
    cfg = AegisConfig(
        database_path=str(tmp_path / "db.sqlite"),
        paths=[str(watch)],
        exclude=["*.log"],
    )
    return cfg, watch


def test_build_baseline_records_files(tmp_path):
    """build_baseline records the files, honouring the exclusions."""
    cfg, watch = _make_config(tmp_path)
    db = Database(cfg.database_path)
    count = build_baseline(cfg, db)
    assert count == 2  # ignore.log e exclus
    assert db.get_file(normalize_path(str(watch / "a.txt"))) is not None
    assert db.get_file(normalize_path(str(watch / "ignore.log"))) is None


def test_compare_detects_all_change_kinds(tmp_path):
    """Modification / creation / deletion are reported correctly."""
    cfg, watch = _make_config(tmp_path)
    db = Database(cfg.database_path)
    build_baseline(cfg, db)

    (watch / "a.txt").write_text("alpha MODIFICAT")   # modified
    (watch / "c.txt").write_text("gamma")             # created
    (watch / "b.conf").unlink()                        # deleted

    kinds = {c.path: c.kind for c in compare_to_baseline(cfg, db)}
    assert kinds[normalize_path(str(watch / "a.txt"))] == "modified"
    assert kinds[normalize_path(str(watch / "c.txt"))] == "created"
    assert kinds[normalize_path(str(watch / "b.conf"))] == "deleted"


def test_no_changes_when_untouched(tmp_path):
    cfg, _ = _make_config(tmp_path)
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    assert compare_to_baseline(cfg, db) == []


def test_trust_mtime_still_detects_real_change(tmp_path):
    """With trust_mtime, untouched files are skipped but a real modification is still detected."""
    cfg, watch = _make_config(tmp_path)
    cfg.trust_mtime = True
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    assert compare_to_baseline(cfg, db) == []      # nimic atins → nimic raportat

    (watch / "a.txt").write_text("new content")   # changes the content (and mtime)
    kinds = {c.path: c.kind for c in compare_to_baseline(cfg, db)}
    assert kinds[normalize_path(str(watch / "a.txt"))] == "modified"
