"""Smoke test: the schema records import and construct."""

from __future__ import annotations

from pipeline.schema import Detection, Finding, Mapping, RunMeta


def test_finding_constructs() -> None:
    finding = Finding(
        finding_id="abc123",
        tool="bandit",
        file="targets/app/views.py",
        line=42,
        rule_id="B608",
        cwe_ids=["CWE-89"],
        severity="HIGH",
        confidence="HIGH",
        message="Possible SQL injection via string-based query construction.",
        raw={"test_id": "B608"},
    )
    assert finding.cwe_ids == ["CWE-89"]
    assert finding.tool == "bandit"


def test_mapping_carries_provenance() -> None:
    mapping = Mapping(
        finding_id="abc123",
        cwe="CWE-89",
        capec_ids=["CAPEC-66"],
        technique_ids=["T1190"],
        method="authoritative",
        chain_evidence={"cwe": "CWE-89", "capec": ["CAPEC-66"], "technique": ["T1190"]},
        confidence="high",
        detection=Detection(data_sources=["Application Log"], sigma_rule_ids=[]),
    )
    assert mapping.method == "authoritative"
    assert mapping.technique_ids == ["T1190"]
    assert mapping.detection.data_sources == ["Application Log"]


def test_detection_defaults_empty() -> None:
    detection = Detection()
    assert detection.data_sources == []
    assert detection.sigma_rule_ids == []


def test_runmeta_constructs() -> None:
    meta = RunMeta(
        attack_version="19.1",
        cwe_version="4.20",
        capec_version="3.9",
        mappings_explorer_commit="47d11bbd8c5163700c888ee7ff9d2bb5bfc66389",
        sigma_release="r2026-04-01",
        tool_versions={"bandit": "1.9.4", "semgrep": "1.168.0"},
    )
    assert meta.attack_version == "19.1"
    assert meta.tool_versions["bandit"] == "1.9.4"
