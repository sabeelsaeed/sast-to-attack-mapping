"""Authoritative CWE -> CAPEC -> ATT&CK mapping (O4).

Follows the CWE catalogue's related CAPECs, then the CAPEC catalogue's ATT&CK
taxonomy mappings. An incomplete chain yields no mapping (the gap goes to the
nlp fallback) rather than a guess.
"""

from __future__ import annotations

from pipeline.bridge.confidence import authoritative_confidence
from pipeline.data.loaders import Catalogues
from pipeline.schema import Detection, Finding, Mapping


def map_finding(finding: Finding, catalogues: Catalogues) -> list[Mapping]:
    """Map a finding via the authoritative chain.

    One mapping per (CWE, technique) reached, sorted by technique id; empty if
    the chain does not complete.
    """
    mappings: list[Mapping] = []

    for cwe in finding.cwe_ids:
        cwe_entry = catalogues.cwe.get(cwe)
        if cwe_entry is None:
            continue

        # technique -> {capec_id: name} supporting it (keep the many-to-many)
        by_technique: dict[str, dict[str, str]] = {}
        for capec_id in cwe_entry.related_capec_ids:
            capec_entry = catalogues.capec.get(capec_id)
            if capec_entry is None:
                continue
            for technique_id in capec_entry.technique_ids:
                by_technique.setdefault(technique_id, {})[capec_id] = capec_entry.name

        for technique_id in sorted(by_technique):
            supporting = by_technique[technique_id]
            technique = catalogues.attack.technique(technique_id)
            mappings.append(
                Mapping(
                    finding_id=finding.finding_id,
                    cwe=cwe,
                    capec_ids=sorted(supporting),
                    technique_ids=[technique_id],
                    method="authoritative",
                    chain_evidence={
                        "cwe": cwe,
                        "capecs": supporting,
                        "technique": {
                            "id": technique_id,
                            "name": technique.name if technique else None,
                        },
                    },
                    confidence=authoritative_confidence(len(supporting)),
                    detection=Detection(),
                )
            )

    return mappings
