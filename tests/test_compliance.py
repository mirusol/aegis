import textwrap

from aegis.config import AegisConfig
from aegis.compliance import engine
from aegis.compliance.checks import (
    check_file_content,
    check_file_exists,
    check_file_permission,
)
from aegis.compliance.rule_loader import load_ruleset


def _write_ruleset(tmp_path, existing_file):
    rules = tmp_path / "rules.yaml"
    rules.write_text(textwrap.dedent(f"""
        metadata: {{os: test}}
        rules:
          - id: "T.1"
            title: "file exists"
            severity: high
            check: {{type: file_exists, path: "{existing_file.as_posix()}", should_exist: true}}
          - id: "T.2"
            title: "intentional failure"
            severity: critical
            check: {{type: file_exists, path: "{(tmp_path / 'nope').as_posix()}", should_exist: true}}
    """), encoding="utf-8")
    return rules


def test_load_ruleset_parses_yaml(tmp_path):
    f = tmp_path / "present.txt"
    f.write_text("x")
    rules = load_ruleset(str(_write_ruleset(tmp_path, f)))
    assert [r.id for r in rules] == ["T.1", "T.2"]
    assert rules[0].severity == "high"


def test_file_exists_check(tmp_path):
    f = tmp_path / "present.txt"
    f.write_text("x")
    assert check_file_exists({"path": str(f), "should_exist": True}).passed
    assert not check_file_exists({"path": str(f), "should_exist": False}).passed


def test_file_content_check(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("PermitRootLogin no\n")
    assert check_file_content({"path": str(f), "contains": "PermitRootLogin no"}).passed
    assert check_file_content({"path": str(f), "not_contains": "PermitRootLogin yes"}).passed


def test_file_permission_check(tmp_path):
    """Tests the permission-comparison LOGIC, independent of the platform.

    We do not rely on os.chmod (ignored on Windows, see checks.check_file_permission),
    and derive the expectations from the file's real mode instead.
    """
    import os
    import stat
    f = tmp_path / "secret"
    f.write_text("x")
    actual = stat.S_IMODE(os.stat(str(f)).st_mode)

    # a mask equal to the current bits: 'max' passes, 'exact' passes
    exact = f"{actual:04o}"
    assert check_file_permission({"path": str(f), "mode": exact, "comparison": "max"}).passed
    assert check_file_permission({"path": str(f), "mode": exact, "comparison": "exact"}).passed

    # a more permissive mask (all bits) passes in 'max' mode
    assert check_file_permission({"path": str(f), "mode": "0777", "comparison": "max"}).passed

    # if the file has any bit set, a mask excluding it must FAIL ('max')
    if actual != 0:
        stricter = f"{actual & ~ (actual & -actual):04o}"  # drops the lowest set bit
        assert not check_file_permission({"path": str(f), "mode": stricter, "comparison": "max"}).passed


def test_engine_counts_pass_and_fail(tmp_path):
    f = tmp_path / "present.txt"
    f.write_text("x")
    cfg = AegisConfig(ruleset=str(_write_ruleset(tmp_path, f)))
    report = engine.run(cfg)
    assert report.total == 2
    assert report.passed_count == 1
    assert report.failed_count == 1
    assert report.has_failures_at_or_above("critical") is True
