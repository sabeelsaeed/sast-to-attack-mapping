"""Evaluation metric tests — hermetic, synthetic mapping dicts."""

from __future__ import annotations

from eval.metrics import (
    coverage,
    data_source_yield,
    method_agreement,
    plausibility,
    plausibility_sample,
    sigma_yield,
)


def _m(finding_id: str, method: str, techs: list[str], sigma=(), sources=()) -> dict:
    return {
        "finding_id": finding_id,
        "cwe": "CWE-1",
        "technique_ids": techs,
        "method": method,
        "confidence": "high",
        "detection": {"sigma_rule_ids": list(sigma), "data_sources": list(sources)},
    }


def test_coverage_splits_authoritative_and_combined() -> None:
    mappings = [
        _m("f1", "authoritative", ["T1"]),
        _m("f2", "nlp", ["T2"]),
    ]
    cov = coverage(mappings, n_findings=4)
    assert cov["authoritative"] == 0.25  # 1/4
    assert cov["combined"] == 0.5  # 2/4


def test_method_agreement_bounds() -> None:
    assert method_agreement({"f": {"T1"}}, {"f": {"T1"}})["mean_jaccard"] == 1.0
    assert method_agreement({"f": {"T1"}}, {"f": {"T2"}})["mean_jaccard"] == 0.0
    partial = method_agreement({"f": {"T1", "T2"}}, {"f": {"T2", "T3"}})
    assert partial["mean_jaccard"] == round(1 / 3, 4)
    assert partial["any_overlap_rate"] == 1.0


def test_agreement_ignores_findings_only_one_method_mapped() -> None:
    res = method_agreement({"f1": {"T1"}, "f2": set()}, {"f1": {"T9"}, "f2": {"T2"}})
    assert res["comparable_findings"] == 1  # only f1 has both


def test_detection_yields_are_separate() -> None:
    mappings = [
        _m("f1", "authoritative", ["T1"], sigma=["r1"], sources=["Process Creation"]),
        _m("f2", "nlp", ["T2"], sigma=(), sources=["Network Traffic"]),
    ]
    assert sigma_yield(mappings) == 0.5  # only 1 of 2 has a Sigma rule
    assert data_source_yield(mappings) == 1.0  # both have a data source


def test_plausibility_from_labels() -> None:
    labels = [
        {"plausible": "1"},
        {"plausible": "0"},
        {"plausible": ""},  # unlabelled, ignored
    ]
    p = plausibility(labels)
    assert p["n_labelled"] == 2
    assert p["plausible_rate"] == 0.5


def test_plausibility_sample_is_deterministic() -> None:
    mappings = [_m(f"f{i}", "nlp", [f"T{i}"]) for i in range(20)]
    a = plausibility_sample(mappings, 5, seed=42)
    b = plausibility_sample(mappings, 5, seed=42)
    assert a == b
    assert len(a) == 5
    assert set(a[0].keys()) == {
        "finding_id",
        "cwe",
        "technique_id",
        "method",
        "confidence",
        "plausible",
        "notes",
    }
