"""Normalize Bandit/Semgrep JSON into the common Finding schema (O3)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pipeline.schema import Finding

_CWE_RE = re.compile(r"CWE-\d+")


def _finding_id(tool: str, file: str, line: int, rule_id: str) -> str:
    key = f"{tool}|{file}|{line}|{rule_id}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def _normalize_bandit(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in data.get("results", []):
        file = r["filename"]
        line = r["line_number"]
        rule_id = r["test_id"]
        cwe = r.get("issue_cwe") or {}
        cwe_ids = [f"CWE-{cwe['id']}"] if cwe.get("id") is not None else []
        findings.append(
            Finding(
                finding_id=_finding_id("bandit", file, line, rule_id),
                tool="bandit",
                file=file,
                line=line,
                rule_id=rule_id,
                cwe_ids=cwe_ids,
                severity=r.get("issue_severity", ""),
                confidence=r.get("issue_confidence", ""),
                message=r.get("issue_text", ""),
                raw=r,
            )
        )
    return findings


def _normalize_semgrep(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for r in data.get("results", []):
        file = r["path"]
        line = r["start"]["line"]
        rule_id = r["check_id"]
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        # semgrep tags CWE as strings like "CWE-89: ..."
        cwe_ids = [
            m.group() for c in metadata.get("cwe", []) if (m := _CWE_RE.search(c))
        ]
        findings.append(
            Finding(
                finding_id=_finding_id("semgrep", file, line, rule_id),
                tool="semgrep",
                file=file,
                line=line,
                rule_id=rule_id,
                cwe_ids=cwe_ids,
                severity=extra.get("severity", ""),
                confidence=metadata.get("confidence", ""),
                message=extra.get("message", ""),
                raw=r,
            )
        )
    return findings


def _detect_and_normalize(data: dict) -> list[Finding]:
    results = data.get("results", [])
    if results and "test_id" in results[0]:
        return _normalize_bandit(data)
    if results and "check_id" in results[0]:
        return _normalize_semgrep(data)
    # empty results: fall back on a top-level key (bandit emits "metrics")
    if "metrics" in data:
        return _normalize_bandit(data)
    return _normalize_semgrep(data)


def normalize_findings(paths: list[Path]) -> list[Finding]:
    """Load scanner JSON files and return common-schema findings."""
    findings: list[Finding] = []
    for path in paths:
        data = json.loads(Path(path).read_text())
        findings.extend(_detect_and_normalize(data))
    return findings
