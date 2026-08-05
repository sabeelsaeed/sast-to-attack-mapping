"""Normalize tests against a real Bandit fixture and a Semgrep one.

Bandit's B105 reports CWE-259 (a gap); the CWE-798 that completes the chain is
exercised via the Semgrep fixture.
"""

from __future__ import annotations

from pathlib import Path

from pipeline.normalize import _finding_id, normalize_findings

FIXTURES = Path(__file__).parent / "fixtures"
BANDIT = FIXTURES / "bandit_sample.json"
SEMGREP = FIXTURES / "semgrep_sample.json"


def test_cwe_extraction() -> None:
    # Bandit B105 (hard-coded password) reports CWE-259 in real output.
    findings = normalize_findings([BANDIT])
    b105 = next(f for f in findings if f.rule_id == "B105")
    assert b105.tool == "bandit"
    assert b105.cwe_ids == ["CWE-259"]


def test_bandit_sql_injection_cwe() -> None:
    findings = normalize_findings([BANDIT])
    b608 = next(f for f in findings if f.rule_id == "B608")
    assert b608.cwe_ids == ["CWE-89"]


def test_semgrep_cwe_parsed_from_metadata_string() -> None:
    findings = normalize_findings([SEMGREP])
    creds = next(f for f in findings if "hardcoded-password" in f.rule_id)
    sqli = next(f for f in findings if "sql-injection" in f.rule_id)
    assert creds.tool == "semgrep"
    assert creds.cwe_ids == ["CWE-798"]
    assert sqli.cwe_ids == ["CWE-89"]


def test_tool_autodetection_mixes_sources() -> None:
    findings = normalize_findings([BANDIT, SEMGREP])
    tools = {f.tool for f in findings}
    assert tools == {"bandit", "semgrep"}


def test_finding_id_is_stable_and_distinct() -> None:
    assert _finding_id("bandit", "a.py", 2, "B105") == _finding_id(
        "bandit", "a.py", 2, "B105"
    )
    assert _finding_id("bandit", "a.py", 2, "B105") != _finding_id(
        "bandit", "a.py", 3, "B105"
    )


def test_normalize_to_bridge_composes() -> None:
    # The Semgrep CWE-798 finding must flow through the authoritative bridge to
    # its ATT&CK techniques — proving normalize -> bridge composition.
    from pipeline.bridge.authoritative import map_finding
    from pipeline.data.loaders import Catalogues

    cats = Catalogues.from_versions()
    creds = next(f for f in normalize_findings([SEMGREP]) if f.cwe_ids == ["CWE-798"])
    techniques = {t for m in map_finding(creds, cats) for t in m.technique_ids}
    assert {"T1552.001", "T1078.001"} <= techniques
