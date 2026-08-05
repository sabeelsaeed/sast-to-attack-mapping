"""Evaluation metrics — the four Table 2 criteria as pure functions (O7).

- coverage (RQ1): % of findings receiving >=1 ATT&CK technique (auth vs combined)
- plausibility (RQ1): sampled mappings validated by a human (no auto gold available)
- method_agreement (RQ2): authoritative vs NLP overlap on the same findings
- detection yield (RQ3): Sigma yield and data-source yield, reported *separately*

All functions are deterministic and operate on plain dicts (the serialized
``Mapping`` shape from ``out/mappings.json``) so eval is decoupled from the
pipeline objects.
"""

from __future__ import annotations

import random

Mapping = dict  # serialized pipeline.schema.Mapping


def _findings_with_technique(mappings: list[Mapping]) -> set[str]:
    return {m["finding_id"] for m in mappings if m["technique_ids"]}


def coverage(mappings: list[Mapping], n_findings: int) -> dict:
    """Fraction of findings receiving >=1 technique — authoritative vs combined."""
    auth = _findings_with_technique(
        [m for m in mappings if m["method"] == "authoritative"]
    )
    combined = _findings_with_technique(mappings)
    return {
        "n_findings": n_findings,
        "authoritative": round(len(auth) / n_findings, 4) if n_findings else 0.0,
        "combined": round(len(combined) / n_findings, 4) if n_findings else 0.0,
    }


def method_agreement(
    auth_by_finding: dict[str, set[str]],
    nlp_by_finding: dict[str, set[str]],
) -> dict:
    """Authoritative vs NLP overlap over findings both mapped.

    Takes finding_id -> technique-id sets for each path; returns mean Jaccard,
    the share with >=1 shared technique, and the count compared.
    """
    shared_ids = [
        fid
        for fid in auth_by_finding
        if auth_by_finding.get(fid) and nlp_by_finding.get(fid)
    ]
    if not shared_ids:
        return {"comparable_findings": 0, "mean_jaccard": 0.0, "any_overlap_rate": 0.0}

    jaccards = []
    any_overlap = 0
    for fid in shared_ids:
        a, b = auth_by_finding[fid], nlp_by_finding[fid]
        union = a | b
        inter = a & b
        jaccards.append(len(inter) / len(union))
        if inter:
            any_overlap += 1
    n = len(shared_ids)
    return {
        "comparable_findings": n,
        "mean_jaccard": round(sum(jaccards) / n, 4),
        "any_overlap_rate": round(any_overlap / n, 4),
    }


def sigma_yield(mappings: list[Mapping]) -> float:
    """Fraction of mappings carrying >=1 Sigma rule (RQ3)."""
    if not mappings:
        return 0.0
    hit = sum(1 for m in mappings if m["detection"]["sigma_rule_ids"])
    return round(hit / len(mappings), 4)


def data_source_yield(mappings: list[Mapping]) -> float:
    """Fraction of mappings carrying >=1 ATT&CK data source (RQ3)."""
    if not mappings:
        return 0.0
    hit = sum(1 for m in mappings if m["detection"]["data_sources"])
    return round(hit / len(mappings), 4)


def plausibility(labels: list[dict]) -> dict:
    """Plausibility from a filled label sheet (rows with a ``plausible`` 0/1)."""
    scored = [row for row in labels if str(row.get("plausible", "")).strip() != ""]
    if not scored:
        return {"n_labelled": 0, "plausible_rate": 0.0}
    truthy = {"1", "yes", "true"}
    plausible = sum(1 for row in scored if str(row["plausible"]).strip() in truthy)
    return {
        "n_labelled": len(scored),
        "plausible_rate": round(plausible / len(scored), 4),
    }


def plausibility_sample(mappings: list[Mapping], n: int, seed: int = 42) -> list[dict]:
    """Deterministic seeded sample of mappings for manual plausibility labelling."""
    rng = random.Random(seed)
    ordered = sorted(mappings, key=lambda m: (m["finding_id"], m["technique_ids"]))
    chosen = ordered if n >= len(ordered) else rng.sample(ordered, n)
    chosen.sort(key=lambda m: (m["finding_id"], m["technique_ids"]))
    return [
        {
            "finding_id": m["finding_id"],
            "cwe": m["cwe"],
            "technique_id": m["technique_ids"][0] if m["technique_ids"] else "",
            "method": m["method"],
            "confidence": m["confidence"],
            "plausible": "",  # human fills: 1 = plausible, 0 = not
            "notes": "",
        }
        for m in chosen
    ]
