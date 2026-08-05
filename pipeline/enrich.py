"""Attach detection guidance to mapped techniques (O6).

Fills each mapping's Detection with Sigma rule ids (indexed by ATT&CK technique
tag) and ATT&CK data-source names. Indexes are built once and passed to enrich().
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeline.schema import Detection, Mapping

# Sigma technique tag, e.g. "attack.t1190" or "attack.t1059.001".
_TECH_TAG = re.compile(r"^attack\.t(\d+(?:\.\d+)?)$", re.IGNORECASE)


class SigmaIndex:
    """Index of SigmaHQ rules keyed by ATT&CK technique id (``T####``)."""

    def __init__(self, sigma_dir: Path) -> None:
        self.by_technique: dict[str, list[str]] = {}
        self._build(Path(sigma_dir))

    def _build(self, sigma_dir: Path) -> None:
        collected: dict[str, set[str]] = {}
        for path in sigma_dir.rglob("*.yml"):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue  # tolerate malformed / unreadable rule files
            if not isinstance(doc, dict):
                continue
            rule_id = doc.get("id")
            if not rule_id:
                continue
            for tag in doc.get("tags", []) or []:
                match = _TECH_TAG.match(str(tag))
                if match:
                    tid = f"T{match.group(1).upper()}"
                    collected.setdefault(tid, set()).add(str(rule_id))
        self.by_technique = {tid: sorted(ids) for tid, ids in collected.items()}

    def rules_for(self, technique_id: str) -> list[str]:
        """Sigma rule ids tagged with this technique (empty if none)."""
        return self.by_technique.get(technique_id, [])


def enrich(
    mapping: Mapping,
    sigma_index: SigmaIndex,
    data_source_index: dict[str, list[str]],
) -> Mapping:
    """Fill the mapping's detection from Sigma rules + ATT&CK data sources."""
    sigma_rules: set[str] = set()
    data_sources: set[str] = set()
    for technique_id in mapping.technique_ids:
        sigma_rules.update(sigma_index.rules_for(technique_id))
        data_sources.update(data_source_index.get(technique_id, []))
    mapping.detection = Detection(
        data_sources=sorted(data_sources),
        sigma_rule_ids=sorted(sigma_rules),
    )
    return mapping
