"""Enrichment tests — Sigma index over hermetic fixtures + real ATT&CK sources."""

from __future__ import annotations

from pathlib import Path

import pytest

from pipeline.data.loaders import Catalogues
from pipeline.enrich import SigmaIndex, enrich
from pipeline.schema import Mapping

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma"


@pytest.fixture(scope="module")
def sigma_index() -> SigmaIndex:
    return SigmaIndex(SIGMA_FIXTURES)


def _mapping(technique_id: str) -> Mapping:
    return Mapping(
        finding_id="f1",
        cwe="CWE-798",
        capec_ids=["CAPEC-70"],
        technique_ids=[technique_id],
        method="authoritative",
        chain_evidence={},
        confidence="high",
    )


def test_sigma_index_maps_technique_and_subtechnique(sigma_index: SigmaIndex) -> None:
    assert sigma_index.rules_for("T1190") == ["11111111-1111-1111-1111-111111111111"]
    assert sigma_index.rules_for("T1078.001") == [
        "22222222-2222-2222-2222-222222222222"
    ]


def test_sigma_index_ignores_tactic_tags(sigma_index: SigmaIndex) -> None:
    # "attack.initial-access" / "attack.defense-evasion" must not become keys.
    assert all(k.startswith("T") for k in sigma_index.by_technique)


def test_enrich_attaches_sigma_and_data_sources(sigma_index: SigmaIndex) -> None:
    ds_index = Catalogues.from_versions().attack.data_source_index()
    m = enrich(_mapping("T1190"), sigma_index, ds_index)
    assert "11111111-1111-1111-1111-111111111111" in m.detection.sigma_rule_ids
    assert "Application Log Content" in m.detection.data_sources


def test_enrich_empty_when_no_detection(sigma_index: SigmaIndex) -> None:
    # A technique absent from both indexes yields an empty (but valid) Detection.
    m = enrich(_mapping("T9999"), sigma_index, {})
    assert m.detection.sigma_rule_ids == []
    assert m.detection.data_sources == []
