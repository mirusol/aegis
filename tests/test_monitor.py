from aegis.config import AegisConfig
from aegis.core import monitor
from aegis.core.baseline import build_baseline
from aegis.core.database import Database


class _RecordingNotifier:
    def __init__(self):
        self.alerts = []

    def alert(self, message, severity="info"):
        self.alerts.append((severity, message))


def _setup(tmp_path):
    watch = tmp_path / "w"
    watch.mkdir()
    (watch / "raport.docx").write_text("continut initial")
    cfg = AegisConfig(database_path=str(tmp_path / "db.sqlite"),
                      paths=[str(watch)], integrity_enabled=False)
    db = Database(cfg.database_path)
    build_baseline(cfg, db)
    return cfg, db, watch


def test_event_modificare(tmp_path):
    cfg, db, watch = _setup(tmp_path)
    notifier = _RecordingNotifier()
    (watch / "raport.docx").write_text("continut modificat de atacator")
    monitor.handle_fs_event(cfg, db, notifier, str(watch / "raport.docx"), "modified")
    assert db.recent_events()[0]["change"] == "modified"
    assert any("MODIFICAT" in msg for _, msg in notifier.alerts)


def test_event_creat_si_sters(tmp_path):
    cfg, db, watch = _setup(tmp_path)
    notifier = _RecordingNotifier()
    (watch / "payload.exe").write_text("malware")
    monitor.handle_fs_event(cfg, db, notifier, str(watch / "payload.exe"), "created")
    monitor.handle_fs_event(cfg, db, notifier, str(watch / "raport.docx"), "deleted")
    assert {"created", "deleted"} <= {e["change"] for e in db.recent_events()}


def test_event_exclus_este_ignorat(tmp_path):
    cfg, db, watch = _setup(tmp_path)
    cfg.exclude = ["*.log"]
    notifier = _RecordingNotifier()
    (watch / "app.log").write_text("zgomot")
    monitor.handle_fs_event(cfg, db, notifier, str(watch / "app.log"), "created")
    assert db.recent_events() == []
    assert notifier.alerts == []
