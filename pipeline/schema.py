"""Data shapes shared across the pipeline. Mirrors docs/schema.md."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# authoritative runs first; nlp only on findings the chain didn't resolve
Method = Literal["authoritative", "nlp"]
Confidence = Literal["high", "medium", "low"]


@dataclass
class Finding:
    """A normalized SAST finding (output of normalize)."""

    finding_id: str  # hash of tool+file+line+rule
    tool: Literal["bandit", "semgrep"]
    file: str
    line: int
    rule_id: str  # e.g. "B608"
    cwe_ids: list[str]  # "CWE-<int>"; may be empty
    severity: str
    confidence: str
    message: str
    raw: dict  # original tool record


@dataclass
class Detection:
    """Detection guidance attached by enrich."""

    data_sources: list[str] = field(default_factory=list)
    sigma_rule_ids: list[str] = field(default_factory=list)


@dataclass
class Mapping:
    """A finding-to-technique mapping with its provenance."""

    finding_id: str
    cwe: str
    capec_ids: list[str]  # empty on the nlp path
    technique_ids: list[str]
    method: Method
    chain_evidence: dict  # ids/links traversed
    confidence: Confidence
    detection: Detection = field(default_factory=Detection)


@dataclass
class RunMeta:
    """Version stamp written with each run (echoes data/VERSIONS.txt)."""

    attack_version: str
    cwe_version: str
    capec_version: str
    mappings_explorer_commit: str
    sigma_release: str
    tool_versions: dict = field(default_factory=dict)
