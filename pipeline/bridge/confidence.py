"""Confidence rules for the two bridge paths."""

from __future__ import annotations

from pipeline.schema import Confidence


def authoritative_confidence(supporting_capecs: int) -> Confidence:
    # a direct CWE->CAPEC->ATT&CK taxonomy chain is always high
    return "high"


def nlp_confidence(score: float) -> Confidence:
    # thresholds are evaluation parameters (see O7)
    if score >= 0.60:
        return "high"
    if score >= 0.475:
        return "medium"
    return "low"
