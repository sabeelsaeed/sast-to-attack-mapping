"""Authoritative bridge tests against the real pinned catalogues.

Canonical example CWE-798 (hard-coded credentials) completes the chain;
CWE-89 (SQLi) is the documented gap.
"""

from __future__ import annotations

import pytest

from pipeline.bridge.authoritative import map_finding
from pipeline.bridge.confidence import authoritative_confidence
from pipeline.data.loaders import Catalogues
from pipeline.schema import Finding


@pytest.fixture(scope="module")
def catalogues() -> Catalogues:
    return Catalogues.from_versions()


def _finding(cwe: str) -> Finding:
    return Finding(
        finding_id=f"test-{cwe}",
        tool="bandit",
        file="targets/app/config.py",
        line=1,
        rule_id="B105",
        cwe_ids=[cwe],
        severity="MEDIUM",
        confidence="HIGH",
        message="test finding",
        raw={},
    )


def test_hardcoded_credentials_maps_to_attack(catalogues: Catalogues) -> None:
    mappings = map_finding(_finding("CWE-798"), catalogues)
    techniques = {t for m in mappings for t in m.technique_ids}
    assert {"T1552.001", "T1078.001"} <= techniques
    assert all(m.method == "authoritative" for m in mappings)
    assert all(m.confidence == "high" for m in mappings)


def test_chain_evidence_names_capec(catalogues: Catalogues) -> None:
    mappings = map_finding(_finding("CWE-798"), catalogues)
    t1552 = next(m for m in mappings if m.technique_ids == ["T1552.001"])
    assert t1552.capec_ids  # supporting CAPEC(s) recorded
    assert t1552.chain_evidence["cwe"] == "CWE-798"
    assert t1552.chain_evidence["technique"]["id"] == "T1552.001"
    assert t1552.chain_evidence["capecs"]  # {capec_id: name}


def test_sqli_is_an_unmapped_gap(catalogues: Catalogues) -> None:
    # CWE-89's CAPECs carry no ATT&CK taxonomy mapping in the pinned data, so the
    # authoritative path yields nothing and the finding falls through to NLP.
    assert map_finding(_finding("CWE-89"), catalogues) == []


def test_output_is_deterministic(catalogues: Catalogues) -> None:
    a = map_finding(_finding("CWE-798"), catalogues)
    b = map_finding(_finding("CWE-798"), catalogues)
    assert [m.technique_ids for m in a] == [m.technique_ids for m in b]
    assert [m.technique_ids for m in a] == sorted(m.technique_ids for m in a)


def test_confidence_rule() -> None:
    assert authoritative_confidence(1) == "high"
    assert authoritative_confidence(3) == "high"
