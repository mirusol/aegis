"""Continuous integrity monitoring loop (polling or realtime).

A change is reported once: after the alert the baseline is moved to the new state,
so later cycles only report new differences.
"""

from __future__ import annotations

import time

from aegis.core import baseline as baseline_mod
from aegis.core import integrity, scanner

_SEVERITY = {"deleted": "high", "modified": "high",
             "permission_change": "medium", "created": "medium"}


def run_loop(config, database, notifier) -> None:
    database.init_schema()
    if database.count_files() == 0:
        notifier.alert("Baseline is empty: run 'aegis baseline' first.", "medium")
    if config.integrity_enabled:
        seal = integrity.verify_seal(database, config.integrity_key)
        if seal.status == "tampered":
            notifier.alert(f"[INTEGRITATE] {seal.detail}", "critical")
    if config.monitor_mode == "realtime":
        _run_realtime(config, database, notifier)
    else:
        _run_polling(config, database, notifier)


def _reseal(config, database) -> None:
    if config.integrity_enabled:
        integrity.update_seal(database, config.integrity_key)


def _apply_change(database, change) -> None:
    database.log_event(change.path, change.kind, change.old_hash, change.new_hash)
    if change.kind == "deleted":
        database.delete_file(change.path)
    else:
        record = scanner.collect_metadata(change.path)
        if record is not None:
            database.upsert_file(record)


def _report_changes(changes, database, notifier) -> None:
    for change in changes:
        notifier.alert(change.describe(), _SEVERITY.get(change.kind, "info"))
        _apply_change(database, change)


def _run_polling(config, database, notifier) -> None:
    notifier.alert(
        f"Monitoring (polling) started, interval {config.interval_seconds}s. Ctrl+C to stop.",
        "info",
    )
    try:
        while True:
            changes = baseline_mod.compare_to_baseline(config, database)
            if changes:
                _report_changes(changes, database, notifier)
                _reseal(config, database)
            time.sleep(config.interval_seconds)
    except KeyboardInterrupt:
        notifier.alert("Monitoring stopped.", "info")


def handle_fs_event(config, database, notifier, path: str, kind: str) -> None:
    """Handle a filesystem event (created/modified/deleted) on a file.

    Used by the realtime handler and directly in tests.
    """
    if scanner._is_excluded(path, config.exclude):
        return
    path = scanner.normalize_path(path)
    old = database.get_file(path)
    old_hash = old["hash"] if old else None

    if kind == "deleted":
        if old:
            notifier.alert(f"[DELETED] {path}", "high")
            database.log_event(path, "deleted", old_hash, None)
            database.delete_file(path)
            _reseal(config, database)
        return

    record = scanner.collect_metadata(path, config.hash_algorithm, config.chunk_size)
    if record is None:
        return
    if old is None:
        notifier.alert(f"[NEW FILE] {path}", "medium")
        database.log_event(path, "created", None, record["hash"])
    elif record["hash"] != old_hash:
        notifier.alert(f"[MODIFICAT] {path}", "high")
        database.log_event(path, "modified", old_hash, record["hash"])
    database.upsert_file(record)
    _reseal(config, database)


def _run_realtime(config, database, notifier) -> None:
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        notifier.alert("watchdog is not installed: falling back to 'polling' mode.", "medium")
        _run_polling(config, database, notifier)
        return

    class _Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                handle_fs_event(config, database, notifier, event.src_path, "created")

        def on_modified(self, event):
            if not event.is_directory:
                handle_fs_event(config, database, notifier, event.src_path, "modified")

        def on_deleted(self, event):
            if not event.is_directory:
                handle_fs_event(config, database, notifier, event.src_path, "deleted")

        def on_moved(self, event):
            if not event.is_directory:
                handle_fs_event(config, database, notifier, event.src_path, "deleted")
                handle_fs_event(config, database, notifier, event.dest_path, "created")

    observer = Observer()
    for base in config.paths:
        try:
            observer.schedule(_Handler(), base, recursive=True)
        except (FileNotFoundError, OSError):
            continue
    observer.start()
    notifier.alert("Monitoring (realtime) started. Ctrl+C to stop.", "info")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        notifier.alert("Monitoring stopped.", "info")
        observer.stop()
    observer.join()
