from aegis.alerting.notifier import Notifier


def test_email_channel_composes_and_sends(monkeypatch):
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            captured["host"] = host
            captured["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            captured["tls"] = True

        def login(self, user, password):
            captured["login"] = (user, password)

        def send_message(self, msg):
            captured["msg"] = msg

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)

    Notifier([{
        "type": "email", "smtp_host": "smtp.test", "smtp_port": 587,
        "to": "admin@example.com", "username": "u", "password": "p",
    }]).alert("file modified: /etc/passwd", "high")

    assert captured["host"] == "smtp.test"
    assert captured["login"] == ("u", "p")
    assert captured["msg"]["To"] == "admin@example.com"
    assert "file modified" in captured["msg"].get_content()


def test_logfile_channel_writes(tmp_path):
    logf = tmp_path / "alerts.log"
    Notifier([{"type": "logfile", "path": str(logf)}]).alert("test alert", "medium")
    assert "test alert" in logf.read_text(encoding="utf-8")
