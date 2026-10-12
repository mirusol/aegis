from __future__ import annotations

import time
from pathlib import Path
from typing import Any

try:
    from rich.console import Console
    _console = Console()
except ImportError:
    _console = None

_COLORS = {"info": "cyan", "low": "green", "medium": "yellow",
           "high": "red", "critical": "bold red"}


class Notifier:
    def __init__(self, channels: list[dict[str, Any]]) -> None:
        self.channels = channels or [{"type": "console"}]

    def alert(self, message: str, severity: str = "info") -> None:
        for channel in self.channels:
            ctype = channel.get("type")
            if ctype == "console":
                self._to_console(message, severity)
            elif ctype == "logfile":
                self._to_logfile(channel.get("path", "data/aegis.log"), message, severity)
            elif ctype == "email":
                self._to_email(channel, message, severity)

    def _to_console(self, message: str, severity: str) -> None:
        if _console is not None:
            _console.print(f"[{_COLORS.get(severity, 'white')}]● {severity.upper()}[/] {message}")
        else:
            print(f"● {severity.upper()} {message}")

    def _to_logfile(self, path: str, message: str, severity: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{stamp} [{severity.upper()}] {message}\n")

    def _to_email(self, channel: dict, message: str, severity: str) -> None:
        import smtplib
        from email.message import EmailMessage

        recipients = channel.get("to")
        if isinstance(recipients, str):
            recipients = [recipients]
        if not channel.get("smtp_host") or not recipients:
            self._to_console("email channel: 'smtp_host' or 'to' is missing", "medium")
            return

        msg = EmailMessage()
        msg["Subject"] = (f"{channel.get('subject_prefix', '[Aegis]')} "
                          f"{severity.upper()}: integrity alert")
        msg["From"] = channel.get("from", channel.get("username", "aegis@localhost"))
        msg["To"] = ", ".join(recipients)
        msg.set_content(f"Severitate: {severity.upper()}\n\n{message}\n")

        try:
            with smtplib.SMTP(channel["smtp_host"], int(channel.get("smtp_port", 587)),
                              timeout=15) as server:
                if channel.get("use_tls", True):
                    server.starttls()
                if channel.get("username") and channel.get("password"):
                    server.login(channel["username"], channel["password"])
                server.send_message(msg)
        except (OSError, smtplib.SMTPException) as exc:
            self._to_console(f"email channel failed: {exc}", "medium")
