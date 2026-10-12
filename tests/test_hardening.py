import textwrap

from aegis.config import AegisConfig
from aegis.hardening import remediator


def _ruleset(tmp_path):
    missing = (tmp_path / "lipsa.conf").as_posix()
    existing = tmp_path.as_posix()
    rs = tmp_path / "rules.yaml"
    rs.write_text(textwrap.dedent(f"""
        rules:
          - id: "1.1.1"
            title: "required config file present"
            severity: high
            check: {{type: file_exists, path: "{missing}", should_exist: true}}
            remediation: {{powershell: "echo remediere"}}
          - id: "1.1.2"
            title: "director prezent (trece)"
            severity: low
            check: {{type: file_exists, path: "{existing}", should_exist: true}}
          - id: "2.3.1"
            title: "sensitive setting marked risky"
            severity: high
            check: {{type: file_exists, path: "{missing}", should_exist: true}}
            remediation: {{powershell: "echo remediere", risky: true}}
    """), encoding="utf-8")
    return AegisConfig(ruleset=str(rs))


def test_plan_include_doar_regulile_care_pica(tmp_path):
    by_id = {r.rule_id: r for r in remediator.plan(_ruleset(tmp_path))}
    assert by_id["1.1.1"].status == "would-fix"
    assert by_id["2.3.1"].risky is True
    assert "1.1.2" not in by_id


def test_apply_sare_peste_regulile_riscante(tmp_path):
    by_id = {r.rule_id: r for r in remediator.apply(_ruleset(tmp_path))}
    assert by_id["2.3.1"].status == "skipped-risky"
    # 'echo' does not create the file, so the check still fails
    assert by_id["1.1.1"].status == "still-failing"


def test_apply_only_limiteaza_la_o_regula(tmp_path):
    by_id = {r.rule_id: r for r in remediator.apply(_ruleset(tmp_path), only="1.1.1")}
    assert by_id["2.3.1"].status == "skipped-filter"
