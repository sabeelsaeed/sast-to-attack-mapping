"""NLP fallback tests against the real model + ATT&CK corpus.

Model downloads on first run. Lock structure and determinism, not semantics.
"""

from __future__ import annotations

import pytest

from pipeline.bridge.confidence import nlp_confidence
from pipeline.bridge.nlp import NlpMapper
from pipeline.data.loaders import Catalogues
from pipeline.schema import Finding


@pytest.fixture(scope="module")
def mapper() -> NlpMapper:
    return NlpMapper(Catalogues.from_versions())


def _sqli_finding() -> Finding:
    return Finding(
        finding_id="nlp-sqli",
        tool="bandit",
        file="targets/app/db.py",
        line=4,
        rule_id="B608",
        cwe_ids=["CWE-89"],
        severity="MEDIUM",
        confidence="LOW",
        message="Possible SQL injection via string-based query construction.",
        raw={},
    )


def test_nlp_maps_the_sqli_gap(mapper: NlpMapper) -> None:
    mappings = mapper.map_finding(_sqli_finding())
    assert mappings, "NLP should map the finding the authoritative chain missed"
    m = mappings[0]
    assert m.method == "nlp"
    assert m.capec_ids == []  # no chain hop on the NLP path
    assert m.confidence in {"high", "medium", "low"}
    assert m.chain_evidence["model"].endswith("all-MiniLM-L6-v2")
    assert "score" in m.chain_evidence and "threshold" in m.chain_evidence


def test_nlp_is_deterministic(mapper: NlpMapper) -> None:
    a = mapper.map_finding(_sqli_finding())
    b = mapper.map_finding(_sqli_finding())
    assert [m.technique_ids for m in a] == [m.technique_ids for m in b]
    assert [m.chain_evidence["score"] for m in a] == [
        m.chain_evidence["score"] for m in b
    ]


def test_scores_respect_threshold(mapper: NlpMapper) -> None:
    for m in mapper.map_finding(_sqli_finding()):
        assert m.chain_evidence["score"] >= mapper.threshold


def test_nlp_confidence_boundaries() -> None:
    assert nlp_confidence(0.60) == "high"
    assert nlp_confidence(0.50) == "medium"
    assert nlp_confidence(0.42) == "low"
